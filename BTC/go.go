package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
)

// Constants
const numWorkers = 8
const tempoPonto = 90 * time.Second // 1.5 min
const prefixoLen = 6

// ResultDataStruct
type ResultDataStruct struct {
	Wallet   string
	Key      *big.Int
	Wif      string
	HoraData string
}

// Bitcoin functions
func GenerateWif(privKeyInt *big.Int) string {
	privKeyHex := fmt.Sprintf("%064x", privKeyInt)
	privKeyBytes, _ := hex.DecodeString(privKeyHex)
	extendedKey := append([]byte{byte(0x80)}, privKeyBytes...)
	extendedKey = append(extendedKey, byte(0x01))
	firstSHA := sha256.Sum256(extendedKey)
	secondSHA := sha256.Sum256(firstSHA[:])
	checksum := secondSHA[:4]
	finalKey := append(extendedKey, checksum...)
	return encodeBase58(finalKey)
}

func CreatePublicHash160(privKeyInt *big.Int) []byte {
	privKeyBytes := privKeyInt.Bytes()
	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
	compressedPubKey := privKey.PubKey().SerializeCompressed()
	h := sha256.New()
	h.Write(compressedPubKey)
	sha256Hash := h.Sum(nil)
	r := ripemd160.New()
	r.Write(sha256Hash)
	return r.Sum(nil)
}

func Hash160ToAddress(hash160 []byte) string {
	versionedPayload := append([]byte{0x00}, hash160...)
	firstSHA := sha256.Sum256(versionedPayload)
	secondSHA := sha256.Sum256(firstSHA[:])
	checksum := secondSHA[:4]
	fullPayload := append(versionedPayload, checksum...)
	return encodeBase58(fullPayload)
}

// Base58 encode
var base58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

func encodeBase58(input []byte) string {
	var result []byte
	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	for x.Cmp(zero) != 0 {
		x.DivMod(x, base, mod)
		result = append(result, base58Alphabet[mod.Int64()])
	}

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	for _, b := range input {
		if b != 0 {
			break
		}
		result = append([]byte{base58Alphabet[0]}, result...)
	}

	return string(result)
}

// genKeys: Gera chaves sequencial (+1), pula se varrer todo antes do timer
func genKeys(ctx context.Context, minFaixa *big.Int, maxFaixa *big.Int, keyChannel chan *big.Int) {
	faixaSize := new(big.Int).Sub(maxFaixa, minFaixa)
	pontosTotal := 10000 // 0.01%
	puntoSize := new(big.Int).Div(faixaSize, big.NewInt(int64(pontosTotal)))

	for p := 0; p < pontosTotal; p++ {
		minPonto := new(big.Int).Add(minFaixa, new(big.Int).Mul(puntoSize, big.NewInt(int64(p))))
		maxPonto := new(big.Int).Add(minPonto, puntoSize)
		if p == pontosTotal-1 {
			maxPonto = maxFaixa
		}

		timer := time.NewTimer(tempoPonto)
		privKey := new(big.Int).Set(minPonto) // Inicia sequencial

		for {
			select {
			case <-ctx.Done():
				close(keyChannel)
				return
			case <-timer.C:
				goto nextPonto
			default:
				if privKey.Cmp(maxPonto) >= 0 {
					goto nextPonto // Varrer todo, pule
				}
				keyChannel <- new(big.Int).Set(privKey)
				privKey.Add(privKey, big.NewInt(1)) // Sequencial puro
			}
		}
	nextPonto:
	}
	close(keyChannel)
}

// worker: Checa prefix e completo
func worker(ctx context.Context, id int, walletAlvo string, prefixo string, keyChannel chan *big.Int, resultChannel chan *ResultDataStruct, wg *sync.WaitGroup, mu *sync.Mutex, lastKey *big.Int, chavesTestadas *int64) {
	defer wg.Done()

	for {
		select {
		case privKeyInt, ok := <-keyChannel:
			if !ok {
				return
			}
			if ctx.Err() != nil {
				return
			}

			address := CreatePublicHash160(privKeyInt)
			walletCalc := Hash160ToAddress(address)

			mu.Lock()
			lastKey.Set(privKeyInt)
			atomic.AddInt64(chavesTestadas, 1)
			mu.Unlock()

			if strings.HasPrefix(walletCalc, prefixo) {
				fmt.Printf("Encontrado prefixo coincidente em worker %d: wallet calculada = %s, chave = %064x\n", id+1, walletCalc, privKeyInt)
				if walletCalc == walletAlvo {
					resultChannel <- &ResultDataStruct{
						Wallet:   walletCalc,
						Key:      privKeyInt,
						Wif:      GenerateWif(privKeyInt),
						HoraData: time.Now().Format("2006-01-02 15:04:05"),
					}
					close(resultChannel)
					return
				} else {
					fmt.Printf("Não coincidiu com a wallet alvo: %s != %s\n", walletCalc, walletAlvo)
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// Main
func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Digite a wallet alvo: ")
	walletAlvo, _ := reader.ReadString('\n')
	walletAlvo = strings.TrimSpace(walletAlvo)

	fmt.Print("Digite a start key (hex): ")
	startHex, _ := reader.ReadString('\n')
	startHex = strings.TrimSpace(startHex)

	fmt.Print("Digite a stop key (hex): ")
	stopHex, _ := reader.ReadString('\n')
	stopHex = strings.TrimSpace(stopHex)

	startKey := new(big.Int)
	startKey.SetString(startHex[2:], 16)

	stopKey := new(big.Int)
	stopKey.SetString(stopHex[2:], 16)

	prefixo := walletAlvo[:prefixoLen]

	fmt.Printf("Wallet alvo: %s\nStart key: %s\nStop key: %s\n", walletAlvo, startHex, stopHex)

	rangeTotal := new(big.Int).Sub(stopKey, startKey)

	faixaSize := new(big.Int).Div(rangeTotal, big.NewInt(int64(numWorkers)))
	faixas := make([]struct {
		min *big.Int
		max *big.Int
	}, numWorkers)

	for i := 0; i < numWorkers; i++ {
		minFaixa := new(big.Int).Add(startKey, new(big.Int).Mul(faixaSize, big.NewInt(int64(i))))
		maxFaixa := new(big.Int).Add(minFaixa, faixaSize)
		if i == numWorkers-1 {
			maxFaixa = stopKey
		}
		faixas[i] = struct {
			min *big.Int
			max *big.Int
		}{min: minFaixa, max: maxFaixa}
		fmt.Printf("Worker %d: start %064x, stop %064x\n", i+1, minFaixa, maxFaixa)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	keyChannels := make([]chan *big.Int, numWorkers)
	resultChannel := make(chan *ResultDataStruct, 1)
	found := false
	wg := sync.WaitGroup{}
	lastKeys := make([]big.Int, numWorkers)
	mu := sync.Mutex{}
	var chavesTestadas int64 = 0
	startTime := time.Now()

	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				mu.Lock()
				for i := 0; i < numWorkers; i++ {
					fmt.Printf("Worker %d - Última chave verificada: %064x\n", i+1, &lastKeys[i])
				}
				elapsed := time.Since(startTime).Seconds()
				if elapsed > 0 {
					velocidade := float64(chavesTestadas) / elapsed
					totalEstimado := rangeTotal.Uint64()
					restante := totalEstimado - uint64(chavesTestadas)
					etaSegundos := float64(restante) / velocidade
					eta := time.Duration(etaSegundos) * time.Second
					fmt.Printf("Chaves testadas: %d | Velocidade: %.2f keys/s | ETA: %s\n", chavesTestadas, velocidade, eta)
				}
				mu.Unlock()
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()

	for i := 0; i < numWorkers; i++ {
		keyChannels[i] = make(chan *big.Int, 1000)
		wg.Add(1)
		go worker(ctx, i, walletAlvo, prefixo, keyChannels[i], resultChannel, &wg, &mu, &lastKeys[i], &chavesTestadas)
		go genKeys(ctx, faixas[i].min, faixas[i].max, keyChannels[i])
	}

	go func() {
		res, ok := <-resultChannel
		if ok {
			found = true
			fmt.Printf("Encontrada wallet coincidente!\nWallet: %s\nChave HEX: %064x\nWIF: %s\nHora: %s\n", res.Wallet, res.Key, res.Wif, res.HoraData)
			cancel()
		}
	}()

	wg.Wait()
	if !found {
		fmt.Println("Busca completa. Não encontrou a chave.")
	} else {
		fmt.Println("Busca interrompida. Chave encontrada.")
	}
}