import pycardano
from curl_cffi import requests
import datetime
import time

def main():
    MNEMONIC = ""
    ADDRESSES = 100

    session = requests.Session(impersonate="chrome110")
    global_statistics = {
        "challenges": 0,
        "night" : 0
    }
    hd_wallet = pycardano.crypto.bip32.HDWallet

    master_key = hd_wallet.from_mnemonic(MNEMONIC)
    for address in range(ADDRESSES):
        payment_key_path = master_key.derive_from_path("m/1852'/1815'/" + str(address) + "'/0/" + str(0))
        payment_public_key = payment_key_path.public_key
        payment_verification_key = pycardano.key.PaymentExtendedVerificationKey(payment_public_key)

        staking_key_path = master_key.derive_from_path("m/1852'/1815'/" + str(address) +"'/2/0")
        staking_public_key = staking_key_path.public_key
        staking_verification_key = pycardano.key.StakeExtendedVerificationKey(staking_public_key)

        staked_address = pycardano.Address(
            payment_part=payment_verification_key.hash(),
            staking_part=staking_verification_key.hash(),
            network=pycardano.Network.MAINNET
        )

        address_statistics = get_address_statistics(session, staked_address.encode())

        global_statistics["challenges"] += address_statistics["local"]["crypto_receipts"]
        global_statistics["night"] += address_statistics["local"]["night_allocation"]

        print(f"{staked_address.encode()}: challenges={address_statistics["local"]["crypto_receipts"]}, night={address_statistics["local"]["night_allocation"]/1000000}")

    print(f"{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} TOTAL: challenges={global_statistics["challenges"]}, night={global_statistics["night"]/1000000}")


def get_address_statistics(session, address):
    while True:
        try:
            response = session.get(f"https://scavenger.prod.gd.midnighttge.io/statistics/{address}")
            response.raise_for_status()
            address_statistics = response.json()

            return address_statistics
        except requests.exceptions.RequestException as e:  # ty: ignore
            if e.response.status_code != 429:
                return {"local": {"crypto_receipts": 0, "night_allocation": 0}}
            time.sleep(10)


if __name__ == "__main__":
    main()
