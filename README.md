# dumbski


## Wymagania

- Linux
- `make`
- Kompilator C (`gcc`/`clang`)
- OpenSSL (nagłówki + `libcrypto`)

Na Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev
```

## Build

```sh
make
```

Binarka ląduje w `bin/dumbski`.

## Uruchomienie

```sh
./bin/dumbski <start_dir> <file_name> [max_depth]
```

Przykład:

```sh
./bin/dumbski . kopia.agh 3
```

## Sprzątanie

```sh
make clean
```
