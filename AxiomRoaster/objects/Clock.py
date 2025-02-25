#!/usr/bin/python3

from rich.text import Text
from datetime import datetime

class Clock:
        def __rich__(self) -> Text:
            return Text(datetime.now().ctime(), style="bold magenta", justify="center")

