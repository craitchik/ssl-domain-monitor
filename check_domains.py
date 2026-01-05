import json
from pathlib import Path


def load_domains():
    file_path = Path("domains.json")

    if not file_path.exists():
        raise FileNotFoundError("domains.json bulunamadı")

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data.get("domains", [])


def main():
    print("Domain monitor started")

    domains = load_domains()

    if not domains:
        print("Tanımlı domain bulunamadı")
        return

    print(f"Toplam {len(domains)} domain kontrol edilecek:\n")

    for domain in domains:
        print(f"- {domain}")

    print("\nDomain listesi başarıyla okundu")


if __name__ == "__main__":
    main()
