import time
from datetime import datetime
import platform
import os


def ts():
    return int(time.mktime(datetime.now().timetuple()))


def systype():
    if platform.system() == "Darwin":
        return "Mac"
    elif platform.system() == "Windows":
        return "Win"
    return "Linux"


def determine_default_db_dir():
    if platform.system() == "Darwin":
        return os.path.expanduser("~/Library/Application Support/Bitcoin/")
    elif platform.system() == "Windows":
        return os.path.join(os.environ["APPDATA"], "Bitcoin")
    return os.path.expanduser("~/.bitcoin")
