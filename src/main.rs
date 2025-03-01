use sha2::{Digest, Sha256};
use hex;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Instant, Duration};
use std::env;
use std::cmp::max;
use sysinfo::{System, SystemExt, CpuExt};
use rand::Rng;
use std::io::{self};
use reqwest;
use std::process;
use ethereum_types::U256;
use chrono::Local;
use reqwest::blocking::Client;
use serde_json::json;

fn hash_func(args: &[&[u8]]) -> Vec<u8> {
	let mut hasher = Sha256::new();
	for arg in args {
		hasher.update(arg);
	}
	hasher.finalize().to_vec()
}

fn expand(buf: &mut Vec<Vec<u8>>, space_cost: usize) {
	for s in 1..space_cost {
		let new_hash = hash_func(&[&buf[s - 1]]);
		buf.push(new_hash);
	}
}

fn mix(buf: &mut Vec<Vec<u8>>, delta: usize, salt: &[u8], space_cost: usize, time_cost: usize) {
	for _ in 0..time_cost {
		for s in 0..space_cost {
			let prev = buf[s.saturating_sub(1)].clone();
			buf[s] = hash_func(&[&prev, &buf[s]]);
			
			for i in 0..delta {
				let idx_block = hash_func(&[salt, &i.to_le_bytes()]);
				let other = usize::from_le_bytes(idx_block[..8].try_into().unwrap()) % space_cost;
				buf[s] = hash_func(&[&buf[s], &buf[other]]);
			}
		}
	}
}

fn extract(buf: &Vec<Vec<u8>>) -> Vec<u8> {
	buf.last().unwrap().clone()
}

pub fn pokiohash(password: &str, salt: &str, space_cost: usize, time_cost: usize, delta: usize) -> Vec<u8> {
	let salt_bytes = salt.as_bytes();
	let mut buf = vec![hash_func(&[password.as_bytes(), salt_bytes])];
	
	expand(&mut buf, space_cost);
	mix(&mut buf, delta, salt_bytes, space_cost, time_cost);
	extract(&buf)
}

pub fn pokiohash_hash(password: &str, salt: &str) -> String {
	let hash_bytes = pokiohash(password, salt, 16, 20, 4);
	hex::encode(hash_bytes)
}

fn hash_to_difficulty(hash: &str) -> U256 {
	let hash_value = U256::from_str_radix(hash, 16).unwrap_or(U256::zero());
	let max_value = U256::MAX;
	let difficulty = max_value / hash_value;
	difficulty
}

fn mine(hash_count: Arc<Mutex<u64>>, password: Arc<Mutex<String>>, wallet: String, pserver: String) {
	let mut rng = rand::thread_rng();
	let base_url = format!("{}/mining", pserver);
	let client = Client::new();
	loop {
		let nonce: u64 = rng.gen();
		let salt = format!("{:016x}", nonce);

		let ppassword = password.lock().unwrap().clone();
		
		let mut modified_password = salt.clone();
		if ppassword.len() > 16 {
			modified_password.push_str(&ppassword[16..]);
		}
		
		let parts: Vec<&str> = ppassword.split('-').collect();
		let tdiff: u64 = u64::from_str_radix(parts[2], 16).unwrap_or(0);
		let target_diff = U256::from(tdiff);
		let ncoins: u64 = parts[1].parse().unwrap_or(0);
		
		let hash = pokiohash_hash(&modified_password, &salt);
		let difficulty = hash_to_difficulty(&hash) as U256;

		{
			let mut count = hash_count.lock().unwrap();
			*count += 1;
		}

		if difficulty > target_diff {
			println!("{} Block found. Nonce: {}, Hash: {}", Local::now().format("[%H:%M:%S]").to_string(), salt, hash);
			
			let data = json!({
				"jsonrpc": "2.0",
				"id": "1",
				"method": "submitBlock",
				"coins": ncoins.to_string(),
				"miner": &wallet,
				"nonce": &salt
			});
			
			match client.post(&base_url)
			.header("Content-Type", "application/json")
			.json(&data)
			.send()
			{
				Ok(response) => {
						if let Ok(mining_response) = response.text() {
							println!("{} Response: {}", Local::now().format("[%H:%M:%S]").to_string(), mining_response.trim().to_string());
						}
					}
					Err(e) => println!("{} Error getting template: {}", Local::now().format("[%H:%M:%S]").to_string(), e),
			}
		}
	}
}

fn fetch_password(password: Arc<Mutex<String>>, hash_count: Arc<Mutex<u64>>, pserver: String, wallet: String) {
	let start_time = Instant::now();
	let base_url = format!("{}/mining", pserver);
	let client = Client::new();

	loop {
		let hr = (*hash_count.lock().unwrap() as f64 / start_time.elapsed().as_secs_f64().round()) as u64;
		let tocoins = max(1, (hr / 100) + 1);

		let tocoins_str = if start_time.elapsed().as_secs_f64() < 10.0 {
			"10000".to_string()
		} else {
			tocoins.to_string()
		};

		let data = json!({
			"jsonrpc": "2.0",
			"id": "1",
			"method": "getMiningTemplate",
			"coins": tocoins_str,
			"miner": &wallet
		});
		
		println!("base url: {}", base_url);

		match client.post(&base_url)
			.header("Content-Type", "application/json")
			.json(&data)
			.send()
		{
			Ok(response) => {
				if let Ok(json) = response.json::<serde_json::Value>() {
					if let Some(new_password) = json.get("result").and_then(|r| r.as_str()) {
						let mut password_lock = password.lock().unwrap();
						
						let new_password_cmp = new_password.trim().to_string();
						if new_password_cmp != *password_lock {
							*password_lock = new_password_cmp.clone();
							let npassword = new_password_cmp.clone();
							
							
							let parts: Vec<&str> = npassword.split('-').collect();
							let ntdiff: u64 = u64::from_str_radix(parts[2], 16).unwrap_or(0);
							let nh: u64 = parts[0].parse().unwrap_or(0);
							let ncoins: u64 = parts[1].parse().unwrap_or(0);
							
							println!("{} New template with height {}, diff: {}, target: {} POKIO", 
								Local::now().format("[%H:%M:%S]").to_string(), nh, ntdiff, ncoins);
						}
					}
				}
			}
			Err(e) => println!("{} Error getting template: {}", Local::now().format("[%H:%M:%S]").to_string(), e),
		}

		thread::sleep(Duration::from_secs(10));
	}
}

fn is_valid_eth_wallet(wallet: &str) -> bool {
    wallet.len() == 42 && wallet.starts_with("0x") && wallet[2..].chars().all(|c| c.is_digit(16))
}


fn main() {
	let args: Vec<String> = env::args().collect();
	let num_threads = args.iter().position(|arg| arg == "--t")
		.and_then(|i| args.get(i + 1))
		.and_then(|t| t.parse::<usize>().ok())
		.unwrap_or(1);
		
	let wallet = args.iter().position(|arg| arg == "--w")
		.and_then(|i| args.get(i + 1))
		.map(|s| s.to_string())
		.unwrap_or_else(|| "default_wallet".to_string());
		
	let server = args.iter().position(|arg| arg == "--o")
		.and_then(|i| args.get(i + 1))
		.map(|s| s.to_string())
		.unwrap_or_else(|| "https://pokio.xyz".to_string());
	
	if !is_valid_eth_wallet(&wallet) {
        eprintln!("Error: Invalid Ethereum wallet address.");
        std::process::exit(1);
    }
	
	if wallet == "default_wallet" {
		println!("Usage: pokiominer.exe --w your_wallet_address [OPTIONS]");
		println!();
		println!("Required:");
		println!("  --w wallet	  Provide your wallet address.");
		println!();
		println!("Options:");
		println!("  --o server_url  Specify the server URL to connect to. (default: https://pokio.xyz)");
		println!("  --t threads	 Set the number of threads to use (default: 1).");
		println!();
		println!("Example:");
		println!("  pokiominer.exe --w your_wallet_address --t 4");
		process::exit(0);
	}
	
	let mut sys = System::new_all();
	sys.refresh_all();

	println!("{}", "WARNING: EXPERIMENTAL MINER IN USE");
	println!("{}", "\nYou are currently using the *experimental miner* for the Pokio project. Please note that this miner is strictly for pre-testnet testing purposes only. Any coins mined during this session have NO monetary value and will NOT be transferred to the mainnet.\n");
	println!("{}", "We strongly advise limiting your use of this miner to no more than 30 minutes, just enough to send the necessary statistics and ensure everything is functioning correctly. This will greatly assist us in fine-tuning the system. Your participation, though temporary, is invaluable to the project's progress.\n");
	println!("{}", "Thank you for helping us improve the Pokio experience!\n");

	let total_memory = sys.total_memory() / 1024 / 1024;
	let cpu_model = sys.cpus().get(0).map(|cpu| cpu.brand().to_string()).unwrap_or("Unknown".to_string());

	println!("Total RAM: {}",  format!("{} MB", total_memory));
	println!("CPU Model: {}\n", cpu_model.trim());

	println!("{} Start mining with {} threads...", Local::now().format("[%H:%M:%S]").to_string(), num_threads);

	let hash_count = Arc::new(Mutex::new(0));
	let start_time = Instant::now();

	// template to mine
	let password = Arc::new(Mutex::new("0-0-1000-10000".to_string()));

	let mut handles = vec![];

	// updater thread
	let password_clone = Arc::clone(&password);
	let hash_count_clone = Arc::clone(&hash_count);
	
	let pserver = server.clone();
	let pwallet = wallet.clone();
	handles.push(thread::spawn(move || {
		fetch_password(password_clone, hash_count_clone, pserver, pwallet);
	}));
	
	thread::sleep(Duration::from_secs(2));

	// mining threads
	for _ in 0..num_threads {
		let hash_count_clone = Arc::clone(&hash_count);
		let password_clone = Arc::clone(&password);
		let pwallet = wallet.clone();
		let pserver = server.clone();
		handles.push(thread::spawn(move || {
			mine(hash_count_clone, password_clone, pwallet, pserver);
		}));
	}

	// i/o thread
	let hash_count_clone = Arc::clone(&hash_count);
	thread::spawn(move || {
		loop {
			let mut input = String::new();
			io::stdin().read_line(&mut input).unwrap();
			if input.trim() == "h" {
				let elapsed_secs = start_time.elapsed().as_secs_f64();
				let total_hashes = *hash_count_clone.lock().unwrap();
				let hashrate = total_hashes as f64 / elapsed_secs;
				println!("{} Total Hashrate: {:.2} H/s", Local::now().format("[%H:%M:%S]").to_string(), hashrate);
			}
		}
	});

	for handle in handles {
		handle.join().unwrap();
	}
}
