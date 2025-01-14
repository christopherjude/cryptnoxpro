from time import (
    sleep,
    time
)
from typing import (
    Dict,
    KeysView,
    List,
    ValuesView
)

import cryptnoxpy
from tabulate import tabulate

from . import security
from .ui import print_warning
from ... import config


class ExitException(Exception):
    """
    Exception to handle when the user cancels operation
    """


class TimeoutException(Exception):
    """
    Waiting for card has passed it's waiting time.
    """


class Cards:
    def __init__(self, debug: bool = False):
        self._cards: Dict[int, cryptnoxpy.Card] = {}
        self._cards_by_index: Dict[int, cryptnoxpy.Card] = {}
        self.debug = debug

    def __contains__(self, key: int) -> bool:
        return key in self._cards.keys() or key in self._cards_by_index.keys()

    def __delitem__(self, key: int) -> None:
        self._remove_card(key)

    def __getitem__(self, key: int) -> cryptnoxpy.Card:
        if key is None:
            self.refresh()
            self.print_card_list(show_warnings=True)
            return self._select_card

        if key in self._cards.keys() or key in self._cards_by_index.keys():
            try:
                card = self._cards[key]
            except KeyError:
                card = self._cards_by_index[key]

            if card.alive:
                return card

            self._remove_card(card.serial_number)

        self.refresh()
        card = None

        try:
            card = self._cards_by_index[key]
        except KeyError:
            try:
                card = self._cards[key]
            except KeyError:
                card = self._wait_for_card(key)

        return card

    def __len__(self):
        return len(self._cards)

    def refresh(self,remote: bool = False) -> None:
        index = 0

        while True:
            try:
                card = self._cards_by_index[index]
            except KeyError:
                pass
            else:
                if card.alive:
                    index += 1
                    continue
                else:
                    self._remove_card(card.serial_number)

            try:
                self._open_card(index,remote)
            except cryptnoxpy.ReaderException:
                break
            except cryptnoxpy.CryptnoxException:
                pass

            index += 1

    def keys(self) -> KeysView[int]:
        return self._cards.keys()

    def print_card_list(self, show_warnings: bool = False,
                        print_with_one_card: bool = False) -> None:
        """
        Prints list of found Cryptnox cards.

        :param bool show_warnings: Prints warning when cards are not initialized
        :param bool print_with_one_card: Print only if more than one cards are found
        """
        if not self._cards:
            if print_with_one_card:
                print("No cards found.")
            return

        if not print_with_one_card and len(self._cards) == 1:
            return

        data = []

        uninitialized = False
        headers = ["", "Serial number", "Type", "Applet version", "Owner", "Flags"]

        iterator = 1
        for card in self._cards.values():
            info = card.info
            entry = [
                info["serial_number"],
                info["type"],
                info["applet_version"],
                info["name"] + ((" <" + info["email"] + ">") if info["email"]
                                else ""),
                ", ".join(Cards.printable_flags(card))
            ]

            uninitialized |= not info["initialized"]

            entry.insert(0, iterator)
            iterator += 1

            data.append(entry)

        alignment = ["right", ] * len(headers)
        alignment[-1] = "left"
        if data or print_with_one_card:
            print(tabulate(data, headers=headers, colalign=alignment))
            if uninitialized and show_warnings:
                print_warning("UNINITIALIZED CARDS ARE FOUND")
                print(f"To initialize card run : init\n"
                      f"To initialize card in {security.EASY_MODE_TEXT} run : init -e")

    def select_card(self) -> cryptnoxpy.Card:
        self.refresh()
        self.print_card_list(print_with_one_card=True)
        return self._select_card

    def values(self) -> ValuesView[cryptnoxpy.Card]:
        return self._cards.values()

    def _index(self, serial_number: int) -> int:
        for index, card in self._cards_by_index.items():
            if card.serial_number == serial_number:
                return index
        raise ValueError

    def _open_card(self, index: int,remote: bool = False) -> cryptnoxpy.Card:
        connection = cryptnoxpy.Connection(index, self.debug,config._REMOTE_CONNECTIONS,remote)
        card = cryptnoxpy.factory.get_card(connection, self.debug)
        self._cards[card.serial_number] = self._cards_by_index[index] = card

        return card

    def _remove_card(self, key: int) -> None:
        serial_number = index = key
        try:
            serial_number = self._cards_by_index[index].serial_number
        except KeyError:
            try:
                index = next(index for index, card in self._cards_by_index.items() if card.serial_number == key)
            except StopIteration:
                return

        del self._cards[serial_number].connection
        del self._cards[serial_number]
        del self._cards_by_index[index]

    @staticmethod
    def printable_flags(card: cryptnoxpy.Card) -> List[str]:
        flags = []

        if card.initialized:
            flags.append("initialized")
        if card.valid_key:
            try:
                flags.append(f"{card.seed_source.name.lower()} seed")
            except NotImplementedError:
                flags.append("seed")
        if card.pin_authentication:
            flags.append("pin auth")
        if card.pinless_enabled:
            flags.append("pinless")
        if card.extended_public_key:
            flags.append("extended public key")

        keys = []
        for slot_index in cryptnoxpy.SlotIndex:
            try:
                if card.user_key_enabled(slot_index):
                    keys.append(slot_index.name.lower())
            except NotImplementedError:
                break
        if keys:
            flags.append(f'user keys: "{", ".join(keys)}"')

        return flags

    @property
    def _select_card(self) -> cryptnoxpy.Card:
        if not self._cards:
            raise cryptnoxpy.CardException("No Cryptnox cards have been found")

        if len(self._cards) == 1:
            return list(self._cards_by_index.values())[0]

        while True:
            choice = input(f"\nChoose card (1 - {len(self._cards)}) or enter exit : ")
            if choice == "exit":
                raise ExitException()
            try:
                card = list(self._cards_by_index.values())[int(choice) - 1]
            except (ValueError, LookupError, TypeError):
                print("Invalid choice please choose again")
            else:
                break

        return card

    def _wait_for_card(self, card_id: int, timeout: int = 30) -> cryptnoxpy.Card:
        description = f"into reader with index {card_id}" if card_id < 100 else \
            f"with serial number {card_id}"
        print(f"Insert card {description} or press CTRL+C to exit")

        start_time = time()
        card = None

        try:
            while card is None and time() - start_time < timeout:
                self.refresh()
                try:
                    card = self._cards_by_index[card_id]
                except KeyError:
                    try:
                        card = self._cards[card_id]
                    except KeyError:
                        sleep(0.05)
                        continue
                print("Card found. Executing requested command.")
        except KeyboardInterrupt as error:
            raise ExitException("Aborted.") from error

        if time() - start_time >= timeout:
            raise TimeoutException("Timeout reached")

        return card
