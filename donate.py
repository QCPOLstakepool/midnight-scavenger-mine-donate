import pycardano
import requests
import cbor2


DONATION_ADDRESS = "your donation address"
MNEMONIC = "your seed phrase"
WALLETS = 100

def main():
    hd_wallet = pycardano.crypto.bip32.HDWallet
    master_key = hd_wallet.from_mnemonic(MNEMONIC)

    for address in range(WALLETS):
        donate(master_key, address, 0)


def donate(master_key, account, address):
    payment_key_path = master_key.derive_from_path("m/1852'/1815'/" + str(account) + "'/0/" + str(address))
    payment_public_key = payment_key_path.public_key
    payment_verification_key = pycardano.key.PaymentExtendedVerificationKey(payment_public_key)

    staking_key_path = master_key.derive_from_path("m/1852'/1815'/" + str(account) + "'/2/0")
    staking_public_key = staking_key_path.public_key
    staking_verification_key = pycardano.key.StakeExtendedVerificationKey(staking_public_key)

    staked_address = pycardano.Address(
        payment_part=payment_verification_key.hash(),
        staking_part=staking_verification_key.hash(),
        network=pycardano.Network.MAINNET
    )

    if staked_address.encode() == DONATION_ADDRESS:
        return

    payment_signing_key = pycardano.key.PaymentExtendedSigningKey(payment_key_path.xprivate_key)
    signature = sign_cip8(payment_signing_key, staked_address, "Assign accumulated Scavenger rights to: " + DONATION_ADDRESS)

    print("Address ({}/{}): {}".format(account, address, staked_address.encode()))

    result = requests.post("https://scavenger.prod.gd.midnighttge.io/donate_to/" + DONATION_ADDRESS + "/" + staked_address.encode() + "/" + signature)
    print(result.json())


def sign_cip8(signing_key: pycardano.key.PaymentExtendedSigningKey, address: pycardano.Address, message: str):
    address_bytes = bytes(address.to_primitive())
    protected = {1: -8, "address": address_bytes}
    protected_encoded = cbor2.dumps(protected)
    unprotected = {"hashed": False}
    payload = message.encode("utf-8")

    sig_structure = ["Signature1", protected_encoded, b"", payload]
    to_sign = cbor2.dumps(sig_structure)
    signature = signing_key.sign(to_sign)

    cose_sign1 = [protected_encoded, unprotected, payload, signature]
    return cbor2.dumps(cose_sign1).hex()


if __name__ == "__main__":
    main()
