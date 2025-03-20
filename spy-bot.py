import os
import json
import time
import logging
import sys
import requests
import signal
import telebot
import asyncio
import aiohttp
import ssl
import certifi
from dotenv import load_dotenv
import threading

# Load environment variables
load_dotenv()

# API KEYS
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
BLOCKCYPHER_API_KEY = os.getenv("BLOCKCYPHER_API_KEY")  # Optional but recommended

# Validate required variables
if not all([TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID]):
    raise ValueError("Missing required environment variables. Ensure .env is properly configured.")

# Initialize Telegram bot
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("bitcoin_tracker.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# File to store dynamically tracked wallets
WALLET_FILE = "tracked_btc_wallets.txt"
TRANSACTION_HISTORY_FILE = "btc_transaction_history.json"

# BTC API endpoints (using multiple for redundancy)
BTC_APIS = {
    "blockstream": "https://blockstream.info/api",
    "blockcypher": "https://api.blockcypher.com/v1/btc/main",
    "mempool": "https://mempool.space/api"
}

# Create SSL context for secure connections
ssl_context = ssl.create_default_context(cafile=certifi.where())

# Load wallets from file or initialize a default set
if os.path.exists(WALLET_FILE):
    with open(WALLET_FILE, "r") as f:
        WALLETS = set(line.strip() for line in f if line.strip())
else:
    # Initial set of known North Korean hacker-associated BTC addresses
    WALLETS = set([
        "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h",  # Lazarus Group associated
        "12QtD5BFwRsdNsAZY76UVE1xyCGNTojH9h",          # WannaCry ransom address
        "3LCGsSmfr24demGvriN4e3ft8wEcDuHFqh",          # Linked to exchange hacks
        # Add more addresses as needed
    ])



# Known exchange deposit addresses to monitor
EXCHANGES = {
    # Binance deposit addresses
    "3AfUy4DxJWAaDGJ8mKp3JYz9mtHYBqMUfa": "Binance",
    "bc1qx9t2l3pyny2spqpqlye8svce70nppwtaxwdrp4": "Binance",
    # Coinbase deposit addresses
    "3ETUmNhL2JFZa7xmGBQKG7wWPUBs6BgGQk": "Coinbase",
    # Kraken deposit addresses
    "bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97": "Kraken",
}

# Known mixing services and high-risk addresses
MIXERS = {
    "bc1qx9t2l3pyny2spqpqlye8svce70nppwtaxwdrp4": "Wasabi Mixer",
    "bc1qsg9mrqkw2wexrpqmmshfyxt9c2ayfnfhrxpjzn": "Samourai Whirlpool",
    "bc1q5shngj9335rentd6uqlvllf9p33xd4w7s4y046": "ChipMixer",
}

def load_transaction_history():
    if os.path.exists(TRANSACTION_HISTORY_FILE):
        try:
            with open(TRANSACTION_HISTORY_FILE, "r") as f:
                return json.load(f)
        except:
            return {"transactions": []}
    return {"transactions": []}

def save_transaction_history(tx_history):
    with open(TRANSACTION_HISTORY_FILE, "w") as f:
        json.dump(tx_history, f)

# Initialize with empty history
tx_history = load_transaction_history()

def save_wallets():
    """Save the updated wallet list to a file."""
    with open(WALLET_FILE, "w") as f:
        for wallet in WALLETS:
            f.write(wallet + "\n")

def add_wallet(address):
    """Add a new wallet to track."""
    # Basic Bitcoin address validation
    if not (len(address) >= 26 and len(address) <= 35 and
           (address.startswith('1') or address.startswith('3') or address.startswith('bc1'))):
        return False
    
    if address not in WALLETS:
        WALLETS.add(address)
        save_wallets()
        
        # Process historical transactions (only for newly added wallets)
        try:
            # Use threading to avoid blocking the main thread
            threading.Thread(target=process_new_wallet, args=(address,), daemon=True).start()
        except Exception as e:
            logger.error(f"Error processing wallet history: {e}")
        
        return True
    return True  # Return true even if wallet was already tracked

def remove_wallet(address):
    """Remove a wallet from tracking."""
    if address in WALLETS:
        WALLETS.remove(address)
        save_wallets()
        return True
    return False

async def get_balance(address, api="blockstream"):
    """Get current balance of a BTC wallet using multiple API providers."""
    try:
        if api == "blockstream":
            url = f"{BTC_APIS['blockstream']}/address/{address}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=ssl_context) as response:
                    data = await response.json()
                    if "chain_stats" in data:
                        balance_sats = data["chain_stats"]["funded_txo_sum"] - data["chain_stats"]["spent_txo_sum"]
                        return balance_sats / 100000000  # Convert to BTC
                        
        elif api == "blockcypher":
            url = f"{BTC_APIS['blockcypher']}/addrs/{address}/balance"
            if BLOCKCYPHER_API_KEY:
                url += f"?token={BLOCKCYPHER_API_KEY}"
                
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=ssl_context) as response:
                    data = await response.json()
                    if "final_balance" in data:
                        return data["final_balance"] / 100000000  # Convert to BTC
        
        elif api == "mempool":
            url = f"{BTC_APIS['mempool']}/address/{address}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=ssl_context) as response:
                    data = await response.json()
                    if "chain_stats" in data:
                        balance_sats = data["chain_stats"]["funded_txo_sum"] - data["chain_stats"]["spent_txo_sum"]
                        return balance_sats / 100000000  # Convert to BTC
                        
    except Exception as e:
        logger.error(f"Error fetching balance for {address} using {api}: {e}")
        
        # Try fallback API if the primary fails
        if api == "blockstream":
            return await get_balance(address, "blockcypher")
        elif api == "blockcypher":
            return await get_balance(address, "mempool")
    
    return None

async def get_transactions(address, api="blockstream", limit=10):
    """Get recent transactions for a wallet using multiple API providers."""
    try:
        if api == "blockstream":
            url = f"{BTC_APIS['blockstream']}/address/{address}/txs"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=ssl_context) as response:
                    return await response.json()
                    
        elif api == "blockcypher":
            url = f"{BTC_APIS['blockcypher']}/addrs/{address}/full?limit={limit}"
            if BLOCKCYPHER_API_KEY:
                url += f"&token={BLOCKCYPHER_API_KEY}"
                
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=ssl_context) as response:
                    data = await response.json()
                    return data.get("txs", [])
                    
        elif api == "mempool":
            url = f"{BTC_APIS['mempool']}/address/{address}/txs"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=ssl_context) as response:
                    return await response.json()
                    
    except Exception as e:
        logger.error(f"Error fetching transactions for {address} using {api}: {e}")
        
        # Try fallback API if the primary fails
        if api == "blockstream":
            return await get_transactions(address, "blockcypher", limit)
        elif api == "blockcypher":
            return await get_transactions(address, "mempool", limit)
    
    return []

async def get_transaction_details(tx_hash, api="blockstream"):
    """Get detailed information about a specific transaction."""
    try:
        if api == "blockstream":
            url = f"{BTC_APIS['blockstream']}/tx/{tx_hash}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=ssl_context) as response:
                    return await response.json()
                    
        elif api == "blockcypher":
            url = f"{BTC_APIS['blockcypher']}/txs/{tx_hash}"
            if BLOCKCYPHER_API_KEY:
                url += f"?token={BLOCKCYPHER_API_KEY}"
                
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=ssl_context) as response:
                    return await response.json()
                    
        elif api == "mempool":
            url = f"{BTC_APIS['mempool']}/tx/{tx_hash}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=ssl_context) as response:
                    return await response.json()
                    
    except Exception as e:
        logger.error(f"Error fetching transaction details for {tx_hash} using {api}: {e}")
        
        # Try fallback API if the primary fails
        if api == "blockstream":
            return await get_transaction_details(tx_hash, "blockcypher")
        elif api == "blockcypher":
            return await get_transaction_details(tx_hash, "mempool")
    
    return None

async def fetch_addresses_from_hackscan():
    """Fetch BTC addresses from HackScan API and filter for those with balances."""
    logger.info("Fetching BTC addresses from HackScan...")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://hackscan.hackbounty.io/public/hack-address.json", ssl=ssl_context) as response:
                data = await response.json()
                
                if "btc" not in data:
                    logger.error("No BTC addresses found in API response")
                    return []
                
                addresses = data["btc"]
                logger.info(f"Found {len(addresses)} BTC addresses from HackScan")
                
                # Filter addresses with balance
                addresses_with_balance = []
                for address in addresses:
                    try:
                        balance = await get_balance(address)
                        if balance and balance > 0:
                            addresses_with_balance.append(address)
                            logger.info(f"Found address with balance: {address} ({balance:.8f} BTC)")
                            
                            # Add a slight delay to avoid API rate limiting
                            await asyncio.sleep(0.5)
                    except Exception as e:
                        logger.error(f"Error checking balance for {address}: {e}")
                
                logger.info(f"Found {len(addresses_with_balance)} addresses with balance")
                return addresses_with_balance
                
    except Exception as e:
        logger.error(f"Error fetching addresses from HackScan: {e}")
        return []

def analyze_transaction(tx, from_addresses, to_addresses):
    """Analyze a transaction for suspicious patterns."""
    special_actions = []
    risk_level = "🟢 Low"
    
    # Extract transaction amount and fee
    try:
        if "fee" in tx:
            tx_fee = tx["fee"] / 100000000  # Convert to BTC
        else:
            tx_fee = tx.get("fees", 0) / 100000000
            
        # Calculate total value
        value_btc = sum(output.get("value", 0) for output in tx.get("vout", [])) / 100000000
    except:
        tx_fee = 0
        value_btc = 0
    
    # Check for high-value transactions
    if value_btc > 1.0:
        special_actions.append(f"💰 Large transfer: {value_btc:.8f} BTC")
        risk_level = "🟠 Medium"
        
    if value_btc > 10.0:
        risk_level = "🔴 High"
    
    # Check for known exchange addresses
    for addr in to_addresses:
        if addr in EXCHANGES:
            special_actions.append(f"💱 Sending to {EXCHANGES[addr]} exchange")
            
    # Check for potential mixing services
    for addr in to_addresses:
        if addr in MIXERS:
            special_actions.append(f"🔄 Using {MIXERS[addr]} - potential mixing activity")
            risk_level = "🔴 High"
    
    # Check for transaction patterns
    if len(from_addresses) > 5:
        special_actions.append("🔄 Multiple inputs - potential CoinJoin/Mixing")
        risk_level = "🟠 Medium"
        
    if len(to_addresses) > 10:
        special_actions.append("🔄 Multiple outputs - possible peel chain or distribution")
        risk_level = "🟠 Medium"
    
    # Check for high fees (possible priority transaction)
    if tx_fee > 0.001:  # More than 0.001 BTC in fees
        special_actions.append(f"⚡ High fee transaction: {tx_fee:.8f} BTC")
        
    # Check for round number transactions (often associated with OTC deals)
    if abs(value_btc - round(value_btc)) < 0.0001:
        special_actions.append(f"🎯 Round number transaction: exactly {value_btc:.1f} BTC")
        
    return special_actions, risk_level

def should_track_address(address, inputs=None, outputs=None):
    """Determine if a new address should be automatically tracked."""
    # Don't track known exchanges and mixers
    if address in EXCHANGES or address in MIXERS:
        return False
        
    # If it's receiving funds from our tracked wallet
    if inputs and any(addr in WALLETS for addr in inputs):
        # Only track meaningful transfers
        for output in outputs or []:
            if output.get("address") == address:
                value_btc = output.get("value", 0) / 100000000
                if value_btc > 0.1:  # Only track if it received more than 0.1 BTC
                    return True
        
    return False

def process_new_wallet(address, depth=0, max_depth=2):
    """Process historical transactions when adding a new wallet."""
    if depth >= max_depth:
        return
    
    logger.info(f"Processing historical transactions for {address} (depth {depth})")
    
    # This needs to be run in the event loop
    # Since this is called from a thread, we create a new event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        # Get transactions for this wallet
        transactions = loop.run_until_complete(get_transactions(address))
        
        global tx_history
        for tx in transactions[:10]:  
            tx_hash = tx.get("txid", tx.get("hash", ""))
            if not any(item["tx_id"] == tx_hash for item in tx_history["transactions"]):
                tx_history["transactions"].append({
                    "tx_id": tx_hash,
                    "timestamp": int(time.time())
                })

        # Save transaction history
        save_transaction_history(tx_history)
        
        for tx in transactions[:10]:  # Process up to 10 recent transactions
            tx_hash = tx.get("txid", tx.get("hash", ""))
            
            # Get full transaction details
            tx_details = loop.run_until_complete(get_transaction_details(tx_hash))
            if not tx_details:
                continue
                
            # Extract addresses
            input_addresses = []
            output_addresses = []
            outputs = []
            
            # Extract from blockstream format
            if "vin" in tx_details:
                for vin in tx_details["vin"]:
                    if "prevout" in vin and "scriptpubkey_address" in vin["prevout"]:
                        input_addresses.append(vin["prevout"]["scriptpubkey_address"])
            
            if "vout" in tx_details:
                for vout in tx_details["vout"]:
                    if "scriptpubkey_address" in vout:
                        output_addresses.append(vout["scriptpubkey_address"])
                        outputs.append({
                            "address": vout["scriptpubkey_address"],
                            "value": vout.get("value", 0)
                        })
            
            # Extract from blockcypher format
            elif "inputs" in tx_details:
                for inp in tx_details["inputs"]:
                    if "addresses" in inp:
                        input_addresses.extend(inp["addresses"])
                
                for out in tx_details.get("outputs", []):
                    if "addresses" in out:
                        output_addresses.extend(out["addresses"])
                        for addr in out["addresses"]:
                            outputs.append({
                                "address": addr,
                                "value": out.get("value", 0)
                            })
            
            # For each output address, check if we should track it
            for out_addr in output_addresses:
                if out_addr not in WALLETS and should_track_address(out_addr, input_addresses, outputs):
                    logger.info(f"Auto-tracking new address {out_addr} linked to {address}")
                    WALLETS.add(out_addr)
                    save_wallets()
                    
                    # Process this new wallet recursively, but increase depth
                    if depth < max_depth - 1:
                        process_new_wallet(out_addr, depth + 1, max_depth)
        
    except Exception as e:
        logger.error(f"Error in process_new_wallet for {address}: {e}")
    finally:
        loop.close()

async def cleanup_inactive_wallets():
    """Remove wallets that haven't had activity in the last 30 days."""
    current_time = int(time.time())
    inactive_threshold = current_time - (30 * 24 * 60 * 60)  # 30 days
    
    wallets_to_remove = set()
    for wallet in list(WALLETS):  # Create a copy to iterate over
        try:
            # Check last transaction time
            transactions = await get_transactions(wallet, limit=1)
            if not transactions:
                # Keep wallets with balance even if no transactions
                balance = await get_balance(wallet)
                if balance and balance > 0.1:  # Keep wallets with meaningful balance
                    continue
                wallets_to_remove.add(wallet)
                continue
                
            tx = transactions[0]
            tx_time = tx.get("time", tx.get("confirmed", tx.get("received_time", 0)))
            if tx_time and tx_time < inactive_threshold:
                # Check if still has balance
                balance = await get_balance(wallet)
                if not balance or balance < 0.1:  # Remove if inactive and small/no balance
                    wallets_to_remove.add(wallet)
        except Exception as e:
            logger.error(f"Error checking activity for {wallet}: {e}")
    
    # Remove inactive wallets
    for wallet in wallets_to_remove:
        WALLETS.remove(wallet)
        logger.info(f"Removed inactive wallet: {wallet}")
    
    if wallets_to_remove:
        save_wallets()
        logger.info(f"Removed {len(wallets_to_remove)} inactive wallets")


def clean_transaction_history():
    """Remove transactions older than 30 days from history."""
    current_time = int(time.time())
    cutoff_time = current_time - (30 * 24 * 60 * 60)  # 30 days ago
    
    # Filter out old transactions
    tx_history["transactions"] = [
        tx for tx in tx_history["transactions"] 
        if tx.get("timestamp", 0) > cutoff_time
    ]
    
    # Save the cleaned history
    save_transaction_history(tx_history)


async def get_latest_block_height():
    """Get the latest block height."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{BTC_APIS['blockstream']}/blocks/tip/height", ssl=ssl_context) as response:
                return int(await response.text())
    except:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{BTC_APIS['mempool']}/blocks/tip/height", ssl=ssl_context) as response:
                    return int(await response.text())
        except:
            return 0

async def track_wallets():
    """Main function to track transactions on monitored wallets."""
    cleanup_counter = 0  # Counter to trigger cleanup periodically
    
    while True:
        current_time = int(time.time())
        
        # Increment counter
        cleanup_counter += 1
        
        # Run cleanup every 24 hours (12 cycles if you check every 2 minutes)
        if cleanup_counter >= 720:  # 24 hours * 60 minutes / 2 minutes per cycle
            logger.info("Running cleanup of inactive wallets...")
            await cleanup_inactive_wallets()
            clean_transaction_history() 
            cleanup_counter = 0
        
        for wallet in list(WALLETS): 
            try:
                transactions = await get_transactions(wallet)
                
                for tx in transactions[:5]:  # Check last 5 transactions for efficiency
                    tx_hash = tx.get("txid", tx.get("hash", ""))
                    
                    # Skip if already alerted
                    if any(item["tx_id"] == tx_hash for item in tx_history["transactions"]):
                        continue
                    
                    # Get transaction details
                    tx_details = await get_transaction_details(tx_hash)
                    if not tx_details:
                        continue
                    
                    # Check if transaction is recent (within last 10 minutes)
                    tx_time = tx_details.get("time", tx_details.get("confirmed", tx_details.get("received_time", 0)))
                    
                    # First check if we have a timestamp
                    if tx_time:
                        # If transaction is older than 10 minutes, skip it
                        if (current_time - tx_time) > 600:
                            continue
                    # Fallback to block height if no timestamp
                    elif "block_height" in tx_details:
                        latest_block = await get_latest_block_height()
                        # Only process if in the latest few blocks
                        if latest_block - tx_details["block_height"] > 1:
                            continue
                    # If we can't determine recency, be conservative and skip
                    else:
                        continue   

                    # Get transaction details and extract important information
                    tx_details = await get_transaction_details(tx_hash)
                    if not tx_details:
                        continue
                    
                    # Extract addresses
                    input_addresses = []
                    output_addresses = []
                    outputs = []
                    
                    # Extract from blockstream format
                    if "vin" in tx_details:
                        for vin in tx_details["vin"]:
                            if "prevout" in vin and "scriptpubkey_address" in vin["prevout"]:
                                input_addresses.append(vin["prevout"]["scriptpubkey_address"])
                    
                        for vout in tx_details["vout"]:
                            if "scriptpubkey_address" in vout:
                                output_addresses.append(vout["scriptpubkey_address"])
                                outputs.append({
                                    "address": vout["scriptpubkey_address"],
                                    "value": vout.get("value", 0)
                                })
                    
                    # Extract from blockcypher format
                    elif "inputs" in tx_details:
                        for inp in tx_details["inputs"]:
                            if "addresses" in inp:
                                input_addresses.extend(inp["addresses"])
                        
                        for out in tx_details.get("outputs", []):
                            if "addresses" in out:
                                output_addresses.extend(out["addresses"])
                                for addr in out["addresses"]:
                                    outputs.append({
                                        "address": addr,
                                        "value": out.get("value", 0)
                                    })
                    
                    # Skip if no addresses found
                    if not input_addresses or not output_addresses:
                        continue
                    
                    # Calculate transaction value
                    tx_value_sats = sum(output.get("value", 0) for output in outputs)
                    tx_value_btc = tx_value_sats / 100000000
                    
                    # Skip tiny transactions
                    if tx_value_btc < 0.001:
                        continue
                    
                    # Analyze the transaction
                    special_actions, risk_level = analyze_transaction(tx_details, input_addresses, output_addresses)
                    
                    # Format a notification message
                    from_addrs = ", ".join(input_addresses[:2])
                    if len(input_addresses) > 2:
                        from_addrs += f" and {len(input_addresses)-2} more"
                        
                    to_addrs = ", ".join(output_addresses[:2])
                    if len(output_addresses) > 2:
                        to_addrs += f" and {len(output_addresses)-2} more"
                    
                    # Build alert message
                    message = f"🚨 *BTC Transaction Alert*\n" \
                             f"Risk Level: {risk_level}\n\n" \
                             f"💰 Amount: *{tx_value_btc:.8f} BTC*\n" \
                             f"📤 From: `{from_addrs}`\n" \
                             f"📥 To: `{to_addrs}`\n" \
                             f"🔗 TX: `{tx_hash}`\n\n"
                    
                    if special_actions:
                        message += "*Special Notes:*\n" + "\n".join(special_actions) + "\n\n"
                        
                    message += f"[View on Blockstream](https://blockstream.info/tx/{tx_hash})"
                    
                    # Send alert to Telegram
                    bot.send_message(
                        chat_id=TELEGRAM_CHAT_ID,
                        text=message,
                        parse_mode="Markdown",
                        disable_web_page_preview=True
                    )
                    
                    logger.info(f"Alert sent for transaction {tx_hash}")
                    
                    # When alerting, store with timestamp
                    tx_history["transactions"].append({
                        "tx_id": tx_hash,
                        "timestamp": current_time
                    })
                    save_transaction_history(tx_history)
                    
                    # Auto-track new addresses
                    for out_addr in output_addresses:
                        if out_addr not in WALLETS and should_track_address(out_addr, input_addresses, outputs):
                            logger.info(f"Auto-tracking new address {out_addr}")
                            WALLETS.add(out_addr)
                            save_wallets()
                            
                            # Process historical transactions for new wallet in a separate thread
                            threading.Thread(target=process_new_wallet, args=(out_addr,), daemon=True).start()
                    
                    # Prevent rate limiting
                    await asyncio.sleep(1)
            
            except Exception as e:
                logger.error(f"Error processing wallet {wallet}: {e}")
                
        # Save status after each full cycle
        save_transaction_history(tx_history)
                
        # Check again after delay
        await asyncio.sleep(120)  # Check every 2 minutes

# Telegram bot commands
@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    """Handle /start and /help commands."""
    if str(message.chat.id) != TELEGRAM_CHAT_ID:
        bot.reply_to(message, "Unauthorized access.")
        return
        
    bot.reply_to(message, 
                "🔍 *Bitcoin Tracker Bot*\n\n"
                "Commands:\n"
                "/add <address> - Track a new BTC address\n"
                "/remove <address> - Stop tracking an address\n"
                "/list - List all tracked addresses\n"
                "/balance <address> - Get current balance\n"
                "/hackscan - Fetch known hack addresses from HackScan\n"
                "/help - Show this help message\n\n"
                "This bot will automatically alert you about transactions on tracked addresses.",
                parse_mode="Markdown")

@bot.message_handler(commands=['add'])
def add_wallet_command(message):
    """Handle /add command to track a new wallet."""
    if str(message.chat.id) != TELEGRAM_CHAT_ID:
        bot.reply_to(message, "Unauthorized access.")
        return
        
    parts = message.text.split()
    if len(parts) != 2:
        bot.reply_to(message, "Usage: /add <bitcoin_address>")
        return
        
    address = parts[1].strip()
    if add_wallet(address):
        bot.reply_to(message, f"✅ Now tracking address: `{address}`", parse_mode="Markdown")
    else:
        bot.reply_to(message, f"❌ Invalid Bitcoin address: `{address}`", parse_mode="Markdown")

@bot.message_handler(commands=['remove'])
def remove_wallet_command(message):
    """Handle /remove command to stop tracking a wallet."""
    if str(message.chat.id) != TELEGRAM_CHAT_ID:
        bot.reply_to(message, "Unauthorized access.")
        return
        
    parts = message.text.split()
    if len(parts) != 2:
        bot.reply_to(message, "Usage: /remove <bitcoin_address>")
        return
        
    address = parts[1].strip()
    if remove_wallet(address):
        bot.reply_to(message, f"✅ Stopped tracking address: `{address}`", parse_mode="Markdown")
    else:
        bot.reply_to(message, f"❓ Address not found: `{address}`", parse_mode="Markdown")

@bot.message_handler(commands=['list'])
def list_wallets_command(message):
    """Handle /list command to show all tracked wallets."""
    if str(message.chat.id) != TELEGRAM_CHAT_ID:
        bot.reply_to(message, "Unauthorized access.")
        return
        
    if not WALLETS:
        bot.reply_to(message, "No wallets are currently being tracked.")
        return
        
    response = "🔍 *Tracked Bitcoin Addresses:*\n\n"
    
    # Create a separate thread to get balance information
    async def get_wallet_info():
        wallet_info = []
        
        for wallet in WALLETS:
            balance = await get_balance(wallet)
            balance_str = f"{balance:.8f} BTC" if balance is not None else "Unknown"
            wallet_info.append(f"`{wallet}` - {balance_str}")
            
        return wallet_info
    
    # Run in a new event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        wallet_info = loop.run_until_complete(get_wallet_info())
        
        # Split into multiple messages if too large
        chunks = [wallet_info[i:i+10] for i in range(0, len(wallet_info), 10)]
        
        for i, chunk in enumerate(chunks):
            msg = f"🔍 *Tracked Bitcoin Addresses ({i+1}/{len(chunks)}):*\n\n"
            msg += "\n".join(chunk)
            bot.send_message(message.chat.id, msg, parse_mode="Markdown")
            
    except Exception as e:
        logger.error(f"Error listing wallets: {e}")
        bot.reply_to(message, f"Error retrieving wallet information: {str(e)}")
    finally:
        loop.close()

@bot.message_handler(commands=['balance'])
def balance_command(message):
    """Handle /balance command to show current balance of an address."""
    if str(message.chat.id) != TELEGRAM_CHAT_ID:
        bot.reply_to(message, "Unauthorized access.")
        return
        
    parts = message.text.split()
    if len(parts) != 2:
        bot.reply_to(message, "Usage: /balance <bitcoin_address>")
        return
        
    address = parts[1].strip()
    
    # Create a separate thread to get balance information
    async def get_address_balance():
        balance = await get_balance(address)
        if balance is not None:
            return f"💰 Balance of `{address}`:\n*{balance:.8f} BTC*"
        else:
            return f"❌ Could not retrieve balance for `{address}`"
    
    # Run in a new event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        result = loop.run_until_complete(get_address_balance())
        bot.reply_to(message, result, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"Error getting balance: {e}")
        bot.reply_to(message, f"Error retrieving balance: {str(e)}")
    finally:
        loop.close()

@bot.message_handler(commands=['hackscan'])
def hackscan_command(message):
    """Handle /hackscan command to update addresses from HackScan."""
    if str(message.chat.id) != TELEGRAM_CHAT_ID:
        bot.reply_to(message, "Unauthorized access.")
        return
    
    bot.reply_to(message, "🔍 Fetching addresses from HackScan... This may take a few minutes.")
    
    # Run in a new event loop within a thread
    def run_hackscan():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            hack_addresses = loop.run_until_complete(fetch_addresses_from_hackscan())
            
            if hack_addresses:
                added_count = 0
                for address in hack_addresses:
                    if address not in WALLETS:
                        WALLETS.add(address)
                        added_count += 1
                
                # Save the updated wallet list
                save_wallets()
                
                bot.send_message(
                    chat_id=TELEGRAM_CHAT_ID,
                    text=f"✅ Added {added_count} new addresses from HackScan with non-zero balances.\n"
                         f"Total tracked addresses: {len(WALLETS)}",
                    parse_mode="Markdown"
                )
            else:
                bot.send_message(
                    chat_id=TELEGRAM_CHAT_ID,
                    text="❌ No addresses with balance found from HackScan.",
                    parse_mode="Markdown"
                )
        except Exception as e:
            logger.error(f"Error in HackScan command: {e}")
            bot.send_message(
                chat_id=TELEGRAM_CHAT_ID,
                text=f"Error fetching HackScan addresses: {str(e)}",
                parse_mode="Markdown"
            )
        finally:
            loop.close()
    
    # Run in a separate thread
    threading.Thread(target=run_hackscan, daemon=True).start()

def start_bot_polling():
    """Start Telegram bot polling in a separate thread."""
    bot.infinity_polling(timeout=60, long_polling_timeout=30)

async def main():
    """Main function to run the bot."""
    # Log startup
    logger.info("Starting Bitcoin Tracker Bot")
    print("Starting Bitcoin Tracker Bot")
    
    # Declare WALLETS as global first
    global WALLETS
    
    # Check initial wallet balances
    if WALLETS:
        active_wallets = set()
        logger.info("Checking balances of initial wallets...")
        
        for wallet in WALLETS:
            try:
                balance = await get_balance(wallet)
                if balance and balance > 0:
                    active_wallets.add(wallet)
                    logger.info(f"Wallet {wallet} has balance: {balance:.8f} BTC - will be tracked")
                else:
                    logger.info(f"Wallet {wallet} has zero balance - skipping")
            except Exception as e:
                logger.error(f"Error checking balance for {wallet}: {e}")
        
        # Now you can modify WALLETS
        WALLETS = active_wallets
        save_wallets()
        logger.info(f"Filtered down to {len(WALLETS)} wallets with non-zero balances")
    
    # Start Telegram bot polling in a separate thread
    telegram_thread = threading.Thread(target=start_bot_polling, daemon=True)
    telegram_thread.start()
    
    # Announce startup
    try:
        bot.send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text="🚀 *Bitcoin Tracker Bot Started*\n\n"
                f"Tracking {len(WALLETS)} wallet addresses.\n"
                "Use /help to see available commands.",
            parse_mode="Markdown"
        )
    except Exception as e:
        logger.error(f"Failed to send startup message: {e}")
        
    # Fetch and add addresses from HackScan
    try:
        hack_addresses = await fetch_addresses_from_hackscan()
        if hack_addresses:
            for address in hack_addresses:
                if address not in WALLETS:
                    WALLETS.add(address)
                    logger.info(f"Added HackScan address to tracking: {address}")
            
            # Save the updated wallet list
            save_wallets()
            
            # Announce the new addresses
            try:
                bot.send_message(
                    chat_id=TELEGRAM_CHAT_ID,
                    text=f"🔍 *Added {len(hack_addresses)} BTC addresses from HackScan*\n\n"
                        f"These addresses are associated with known hacks and have non-zero balances.",
                    parse_mode="Markdown"
                )
            except Exception as e:
                logger.error(f"Failed to send HackScan update message: {e}")
    except Exception as e:
        logger.error(f"Error processing HackScan addresses: {e}")
    
    # Start tracking wallets
    await track_wallets()

# Handle graceful shutdown
def signal_handler(sig, frame):
    logger.info("Shutting down Bitcoin Tracker Bot...")
    save_transaction_history(tx_history)
    save_wallets()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Start the bot
if __name__ == "__main__":
    asyncio.run(main())