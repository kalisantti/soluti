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
	"github.com/fatih/color"
	"golang.org/x/crypto/ripemd160"
)

// ==================== CONFIG ====================
const numWorkers = 8
const prefixoLen = 6

const arquivoPrefixos = "prefix_hits.txt"
const arquivoEncontrada = "chave_encontrada.txt"

// Result
type ResultDataStruct struct {
	Wallet   string
	Key      *big.Int
	Wif      string
	HoraData string
}

// ==================== FUNÇÕES BITCOIN ====================
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

// ==================== GERAÇÃO ====================
func genKeys(ctx context.Context, minFaixa *big.Int, maxFaixa *big.Int, keyChannel chan *big.Int) {
	faixaSize := new(big.Int).Sub(maxFaixa, minFaixa)
	pontosTotal := 10000
	puntoSize := new(big.Int).Div(faixaSize, big.NewInt(int64(pontosTotal)))

	for p := 0; p < pontosTotal; p++ {
		minPonto := new(big.Int).Add(minFaixa, new(big.Int).Mul(puntoSize, big.NewInt(int64(p))))
		maxPonto := new(big.Int).Add(minPonto, puntoSize)
		if p == pontosTotal-1 {
			maxPonto = maxFaixa
		}

		timer := time.NewTimer(tempoPonto)
		privKey := new(big.Int).Set(minPonto)

		for {
			select {
			case <-ctx.Done():
				close(keyChannel)
				return
			case <-timer.C:
				goto next
			default:
				if privKey.Cmp(maxPonto) >= 0 {
					goto next
				}
				keyChannel <- new(big.Int).Set(privKey)
				privKey.Add(privKey, big.NewInt(1))
			}
		}
	next:
	}
	close(keyChannel)
}

// ==================== WORKER ====================
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
				color.Cyan("╔══════════════════════════════════════════════════════════════════════╗")
				color.Cyan("║ PREFIXO ENCONTRADO - WORKER %d                                            ║", id+1)
				color.Cyan("╚══════════════════════════════════════════════════════════════════════╝")
				fmt.Printf("Wallet calculada: %s\nChave: %064x\n\n", walletCalc, privKeyInt)

				// Salva todo prefixo
				f, _ := os.OpenFile(arquivoPrefixos, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				f.WriteString(fmt.Sprintf("%s:%064x:%s\n", walletCalc, privKeyInt, GenerateWif(privKeyInt)))
				f.Close()

				if walletCalc == walletAlvo {
					color.Green("╔══════════════════════════════════════════════════════════════════════╗")
					color.Green("║ CHAVE ENCONTRADA!!!                                                  ║")
					color.Green("╚══════════════════════════════════════════════════════════════════════╝")
					resultChannel <- &ResultDataStruct{
						Wallet:   walletCalc,
						Key:      privKeyInt,
						Wif:      GenerateWif(privKeyInt),
						HoraData: time.Now().Format("2006-01-02 15:04:05"),
					}
					return
				} else {
					color.Yellow("→ Apenas prefixo (não é a wallet alvo)\n")
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// ==================== MAIN ====================
var tempoPonto time.Duration

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

	fmt.Print("Tempo por ponto (minutos, ex: 1.5 ou 2): ")
	var minutos float64
	fmt.Scanln(&minutos)
	tempoPonto = time.Duration(minutos * float64(time.Minute))

	startKey := new(big.Int)
	startKey.SetString(startHex[2:], 16)
	stopKey := new(big.Int)
	stopKey.SetString(stopHex[2:], 16)

	prefixo := walletAlvo[:prefixoLen]

	color.Cyan("╔══════════════════════════════════════════════════════════════════════╗")
	color.Cyan("║                     BUSCA BTC PUZZLE INICIADA                        ║")
	color.Cyan("╚══════════════════════════════════════════════════════════════════════╝")

	fmt.Printf("Wallet alvo : %s\n", walletAlvo)
	fmt.Printf("Start key   : %s\n", startHex)
	fmt.Printf("Stop key    : %s\n", stopHex)
	fmt.Printf("Tempo por ponto: %.1f minutos\n\n", minutos)

	// ====================== DIVISÃO ======================
	rangeTotal := new(big.Int).Sub(stopKey, startKey)
	faixaSize := new(big.Int).Div(rangeTotal, big.NewInt(int64(numWorkers)))
	faixas := make([]struct{ min, max *big.Int }, numWorkers)

	for i := 0; i < numWorkers; i++ {
		minFaixa := new(big.Int).Add(startKey, new(big.Int).Mul(faixaSize, big.NewInt(int64(i))))
		maxFaixa := new(big.Int).Add(minFaixa, faixaSize)
		if i == numWorkers-1 {
			maxFaixa = stopKey
		}
		faixas[i] = struct{ min, max *big.Int }{minFaixa, maxFaixa}
		color.Blue("Worker %d → start %064x | stop %064x", i+1, minFaixa, maxFaixa)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	keyChannels := make([]chan *big.Int, numWorkers)
	resultChannel := make(chan *ResultDataStruct, 1)
	wg := sync.WaitGroup{}
	lastKeys := make([]big.Int, numWorkers)
	mu := sync.Mutex{}
	var chavesTestadas int64 = 0
	startTime := time.Now()
	found := false

	// Ticker 10s
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for range ticker.C {
			if ctx.Err() != nil {
				return
			}
			mu.Lock()
			for i := 0; i < numWorkers; i++ {
				color.Magenta("Worker %d → Última chave: %064x", i+1, &lastKeys[i])
			}
			elapsed := time.Since(startTime).Seconds()
			if elapsed > 0 {
				vel := float64(chavesTestadas) / elapsed
				restante := rangeTotal.Uint64() - uint64(chavesTestadas)
				eta := time.Duration(float64(restante)/vel) * time.Second
				color.White("Chaves testadas: %d | Velocidade: %.2f keys/s | ETA: %s", chavesTestadas, vel, eta)
			}
			mu.Unlock()
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
			color.Green("╔══════════════════════════════════════════════════════════════════════╗")
			color.Green("║                     CHAVE ENCONTRADA!!!                              ║")
			color.Green("╚══════════════════════════════════════════════════════════════════════╝")
			fmt.Printf("Wallet: %s\nHEX: %064x\nWIF: %s\n", res.Wallet, res.Key, res.Wif)

			f, _ := os.OpenFile(arquivoEncontrada, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			f.WriteString(fmt.Sprintf("%s:%064x:%s\n", res.Wallet, res.Key, res.Wif))
			f.Close()

			cancel()
		}
	}()

	wg.Wait()
	if !found {
		color.Red("Busca completa. Não encontrou a chave.")
	} else {
		color.Green("Busca interrompida. Chave encontrada.")
	}
}