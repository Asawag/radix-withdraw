import requests, secrets
from radix_engine_toolkit import *
from pathlib import Path
import json
import sys


def load_account(json_file_path: Path, account_number: int) -> dict:
    """
    Load account details from JSON file.
    """
    with open(json_file_path, 'r') as file:
        accounts = json.load(file)
    return accounts[account_number - 1]
def send_str_manifest(str_manifest):
    NETWORK_ID: int = 0x02 #0x01 it's mainnet
    manifest_instructions : Instructions = Instructions().from_string(str_manifest, NETWORK_ID)
    manifest : TransactionManifest = TransactionManifest(manifest_instructions, [])

    def random_nonce() -> int:
        """Generates a random secure random number between 0 and 0xFFFFFFFF (u32::MAX)"""
        return secrets.randbelow(0xFFFFFFFF)

    get_epoch = requests.post('https://stokenet.radixdlt.com/status/gateway-status')  #for Mainnet change it by https://mainnet.radixdlt.com
    ledger_state = get_epoch.json().get('ledger_state', {})
    epoch = ledger_state.get('epoch', None)
    if epoch is None:
        print("Failed to get epoch")
        return
    #print(epoch)
    #sys.exit(1)

    with requests.Session() as s:

        header: TransactionHeader = TransactionHeader(
            network_id=NETWORK_ID,
            start_epoch_inclusive=epoch,
            end_epoch_exclusive=epoch+9,
            nonce=random_nonce(),
            notary_public_key=public_key,
            notary_is_signatory=True, #an actor known as a notary who "seals" the transaction manifest shut after all signers have signed
            tip_percentage=0,
        )

        transaction: NotarizedTransaction = (
            TransactionBuilder()
            .header(header)
            .manifest(manifest)
            .sign_with_private_key(sender_private_key)
            .notarize_with_private_key(sender_private_key)
        )

        try:
            transaction.statically_validate(ValidationConfig.default(NETWORK_ID)) # Ensure that the transaction is statically valid - if the validation fails an exception will be raised.
        except Exception as e:
            print(e)
            print("INVALID TRANSACTION")

        transaction_hash = transaction.intent_hash().as_str() #transaction_hash
        print("transaction_hash:", transaction_hash)
        compiled_transaction = bytearray(transaction.compile()).hex() #notarized_transaction_hex
        payload_submit = {
            "notarized_transaction_hex": compiled_transaction
        }

        response_submit = s.post("https://babylon-stokenet-gateway.radixdlt.com/transaction/submit", json=payload_submit) #for Mainnet change it by https://mainnet.radixdlt.com
        print(response_submit)


# Paths to JSON files storing accounts
json_file_path = Path("accounts_test.json")

sender_account = load_account(json_file_path, 1)
receiver_account = load_account(json_file_path, 2)

sender_private_key_bytes = bytes.fromhex(sender_account["private_key"])
sender_private_key = PrivateKey.new_ed25519(sender_private_key_bytes)
public_key = sender_private_key.public_key()
sender_address = Address(sender_account["account_address"])
receiver_address = Address(receiver_account["account_address"])

#manifest instruction first way :
instructions_list: list[Instruction] = [
    Instruction.CALL_METHOD(
        ManifestAddress.STATIC(Address("account_tdx_2_12ys57aq6w3c28h62az5mpx7snuy3j4hg3sdpgwvhax8alhx78y0ljc")),
        "lock_fee",
        ManifestValue.TUPLE_VALUE(
            [
                ManifestValue.DECIMAL_VALUE(Decimal("2"))
            ]
        )
    ),
    Instruction.CALL_METHOD(
        ManifestAddress.STATIC(Address("account_tdx_2_12ys57aq6w3c28h62az5mpx7snuy3j4hg3sdpgwvhax8alhx78y0ljc")),
        "withdraw",
        ManifestValue.TUPLE_VALUE(
            [
                ManifestValue.ADDRESS_VALUE(ManifestAddress.STATIC(Address("resource_tdx_2_1tknxxxxxxxxxradxrdxxxxxxxxx009923554798xxxxxxxxxtfd2jc"))), # Stokenet XRD
                ManifestValue.DECIMAL_VALUE(Decimal("10"))
            ]
        )
    ),
    Instruction.TAKE_FROM_WORKTOP(
        Address("resource_tdx_2_1tknxxxxxxxxxradxrdxxxxxxxxx009923554798xxxxxxxxxtfd2jc"),
        Decimal("10")
    ),
    Instruction.CALL_METHOD(
        ManifestAddress.STATIC(Address("account_tdx_2_128rp6p6whzl029qgrl5cc2tzczl84um2rfxjn3663sn2td5q0vc00g")),
        "try_deposit_or_abort",
        ManifestValue.TUPLE_VALUE(
            [
                ManifestValue.BUCKET_VALUE(ManifestBucket(0)),
                ManifestValue.ENUM_VALUE(0, [])
            ]
        )
    )
]

instructions: Instructions = Instructions.from_instructions(instructions_list, 2) # 2 = Stokenet
manifest: TransactionManifest = TransactionManifest(instructions, [])
manifest.statically_validate() # No complaints here!

str_manifest = manifest.instructions().as_str()
print(str_manifest) # I propose to print str_manifest so you can see that it's the same that radix-developper-console, so in next script we will just have to put classic transaction manifest, or just behind this line on 'str_manifest'

#str_manifest = """"""

send_str_manifest(str_manifest)
