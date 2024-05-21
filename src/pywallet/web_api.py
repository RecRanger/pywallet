import urllib
import json


balance_site = "https://blockchain.info/q/addressbalance/"
backup_balance_site = "https://api.blockcypher.com/v1/btc/main/addrs/"


def balance(site, address):
    page = urllib.urlopen("%s%s" % (site, address))
    query_result = page.read()
    # If the initial API call returned an error, use a secondary API
    if query_result.startswith("error"):
        page = urllib.urlopen("%s%s" % (backup_balance_site, address))
        query_result = json.loads(page.read())["balance"]
    return query_result
