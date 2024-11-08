use bip38::EncryptWif;

fn main() {
    println!(
        "{:?}",
        "L1qQsUvUbsrcEiRHZY48ySssBuee2y6t9iZEYkxyhMqcCD8ftvgB".encrypt_wif("123456789"),
    );
    println!(
        "{:?}",
        "L1qQsUvUbsrcEiRHZY48ySssBuee2y6t9iZEYkxyhMqcCD8ftvgB".encrypt_wif("当时应当小小小")
    );
    println!(
        "{:?}",
        "L1qQsUvUbsrcEiRHZY48ySssBuee2y6t9iZEYkxyhMqcCD8ftvgB".encrypt_wif("😅😅😅😅😅😅😅")
    );
}
