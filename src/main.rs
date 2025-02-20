use sha2::{Digest, Sha256};
use hex;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Instant};
use std::env;
use sysinfo::{System, SystemExt, CpuExt};
use rand::Rng;
use std::io::{self};

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

pub fn balloon(password: &str, salt: &str, space_cost: usize, time_cost: usize, delta: usize) -> Vec<u8> {
    let salt_bytes = salt.as_bytes();
    let mut buf = vec![hash_func(&[password.as_bytes(), salt_bytes])];
    
    expand(&mut buf, space_cost);
    mix(&mut buf, delta, salt_bytes, space_cost, time_cost);
    extract(&buf)
}

pub fn balloon_hash(password: &str, salt: &str) -> String {
    let hash_bytes = balloon(password, salt, 16, 20, 4);
    hex::encode(hash_bytes)
}

fn hash_to_difficulty(hash: &str) -> f64 {
    let hash_value = u128::from_str_radix(&hash[..32], 16).unwrap_or(0);
    let max_value = u128::MAX;
    (max_value as f64) / (hash_value as f64)
}

fn mine(target_diff: f64, hash_count: Arc<Mutex<u64>>) {
    let password = "1-1-1-1";
    let mut rng = rand::thread_rng();

    loop {
        let nonce: u64 = rng.gen();
        let salt = format!("{:016x}", nonce);
        let hash = balloon_hash(password, &salt);
        let difficulty = hash_to_difficulty(&hash);

        {
            let mut count = hash_count.lock().unwrap();
            *count += 1;
        }

        if difficulty > target_diff {
            println!("\nNonce found: {}", salt);
            println!("Hash: {}", hash);
            println!("Diff: {:.2}", difficulty);
            break;
        }
    }
}

fn main() {
    let mut sys = System::new_all();
    sys.refresh_all();

    let total_memory = sys.total_memory() / 1024 / 1024 ;
    let cpu_model = sys.cpus().get(0).map(|cpu| cpu.brand().to_string()).unwrap_or("Unknown".to_string());

    println!("RAM Memory: {} MB", total_memory);
    println!("CPU: {}", cpu_model);

    let args: Vec<String> = env::args().collect();
    let num_threads = args.iter().position(|arg| arg == "--t")
        .and_then(|i| args.get(i + 1))
        .and_then(|t| t.parse::<usize>().ok())
        .unwrap_or(1);

    println!("Start mining with {} threads...", num_threads);

    let target_diff = 10000.0;
    let hash_count = Arc::new(Mutex::new(0));
    let start_time = Instant::now();

    let mut handles = vec![];

    for _ in 0..num_threads {
        let hash_count_clone = Arc::clone(&hash_count);
        handles.push(thread::spawn(move || {
            mine(target_diff, hash_count_clone);
        }));
    }

    let hash_count_clone = Arc::clone(&hash_count);
    thread::spawn(move || {
        loop {
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            if input.trim() == "h" {
                let elapsed_secs = start_time.elapsed().as_secs_f64();
                let total_hashes = *hash_count_clone.lock().unwrap();
                let hashrate = total_hashes as f64 / elapsed_secs;
                println!("Total Hashrate: {:.2} H/s", hashrate);
            }
        }
    });

    for handle in handles {
        handle.join().unwrap();
    }
}
