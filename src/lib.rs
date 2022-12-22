extern crate core;

use crypto_hashes::blake2::{Blake2b512, Digest};
use rand::Rng;
use std::convert::TryInto;
use std::iter;
use std::time::Instant;
use tokio::sync::broadcast::Sender;
use tokio::task::JoinSet;


#[repr(C)]
pub struct PowHash {
    len: u32,
    data: *const u8,
}

pub struct Challenge {
    difficulty: u32,
    fragments: Vec<[u8; 16]>,
}

pub fn create_challenge(difficulty: u32, num_fragments: usize) -> Challenge {
    // Challenge fragments are 16 bytes of random data
    let fragments = iter::from_fn(|| Some(rand::thread_rng().gen())).take(num_fragments).collect();

    Challenge {
        difficulty,
        fragments,
    }
}

pub struct Solution {
    proofs: Vec<([u8; 16], u128)>,
}

pub async fn solve_challenge(challenge: &Challenge, progress: &Sender<u128>) -> Solution {
    let mut set = JoinSet::new();
    for x in &challenge.fragments {
        set.spawn(solve_fragment(x.clone(), challenge.difficulty));
    }

    let mut result = vec![];
    while let Some(res) = set.join_next().await {
        let solution = res.unwrap();
        result.push(solution);

        // Notify of progress
        progress.send(solution.1).unwrap();
    }

    Solution {
        proofs: result
    }
}

async fn solve_fragment(fragment: [u8; 16], difficulty: u32) -> ([u8; 16], u128) {
    let now = Instant::now();
    let mut nonce: u128 = 0;

    loop {
        if hash_found(fragment, difficulty, nonce) {
            println!(
                "Found in {:?}, after {} hashes!",
                now.elapsed(),
                nonce
            );

            return (fragment, nonce);
        }

        nonce += 1;
    }
}

fn hash_found(fragment: [u8; 16], difficulty: u32, nonce: u128) -> bool {
    let mut hasher = Blake2b512::new();
    hasher.update([fragment, nonce.to_le_bytes()].concat());
    let hash = hasher.finalize();
    let first_four_bytes: [u8; 4] = hash[0..4].try_into().unwrap();

    u32::from_be_bytes(first_four_bytes) < (u32::MAX - difficulty)
}

pub fn verify_solution(challenge: &Challenge, solution: &Solution) -> bool {
    // Does the solution correspond to the challenge
    for f in &challenge.fragments {
        if solution.proofs.iter().find(|p| &p.0 == f).is_none() {
            return false;
        }
    }

    for p in &solution.proofs {
        if !hash_found(p.0, challenge.difficulty, p.1) {
            println!("false");
            return false;
        }
    }

    true
}


#[cfg(test)]
mod tests {
    use tokio::runtime::Runtime;
    use tokio::sync::broadcast::{Receiver, Sender};
    use super::*;

    #[tokio::test]
    async fn it_works() {
        let rt = Runtime::new().unwrap();

        let num_fragments = 4;
        let challenge = create_challenge(4294940000, num_fragments);
        let (tx, mut rx): (Sender<u128>, Receiver<u128>) = tokio::sync::broadcast::channel(num_fragments);

        rt.spawn(async move {
            for _ in 0..num_fragments {
                println!("Broadcast received: {}", rx.recv().await.unwrap());
            }
        });

        let challenge2 = Challenge {
            difficulty: challenge.difficulty,
            fragments: challenge.fragments.clone(),
        };

        let solution = rt.spawn(async move {
            solve_challenge(&challenge2, &tx).await
        }).await.unwrap();

        assert_eq!(verify_solution(&challenge, &solution), true);
        std::mem::forget(rt);
    }
}
