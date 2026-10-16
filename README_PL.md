# Zybex (v1) — rekonstrukcja 6502 / MAC/65

## Wynik i zakres

Pakiet powstał z dostarczonego pliku `Zybex (v1).atr`. Zawiera odtworzony loader, główny obraz programu, mnemoniki standardowego NMOS 6502, proponowane etykiety, makra, dane oraz narzędzia do powtórzenia analizy. Przez „MAC Assembler” przyjęto tutaj **OSS MAC/65**, nie MADS ani ca65.

**Odtworzony ATR jest identyczny bajt w bajt z wejściem.** Weryfikację wykonano dołączonym asemblerem podzbioru MAC/65 napisanym w Pythonie. Nie uruchamiano oryginalnego MAC/65, ATasm ani pełnego emulatora Atari. Zgodność binarna nie oznacza automatycznie kompletnego rozpoznania semantyki wszystkich procedur.

Etykiety są propozycjami z tej analizy, a nie odzyskanymi nazwami autora. Kod i dane nie zostały relokowane, zoptymalizowane ani poprawione. W miejscach bez wystarczającego dowodu wykonywania zachowano `.BYTE`, zamiast sztucznie zamieniać grafikę i tablice w instrukcje.

| Miara | Boot | Główny obraz gry |
|---|---:|---:|
| Zakres RAM w odpowiedniej fazie | $0480–$10FF | $0600–$BC7F |
| Rozmiar obrazu | 3 200 B | 46 720 B |
| Rozpoznane instrukcje | 123 | 6 009 |
| Bajty tych instrukcji | 272 | 12 741 |
| Dane / bajty o niepotwierdzonej roli | 2 928 | 33 979 |
| Ręcznie zaproponowane etykiety kodu | 21 | 125 |
| Wywołania makr | 6 | 74 |

Boot obejmuje również krótki, jawnie zaznaczony fragment kontroli błędu bez odnalezionego poprzednika. Liczba 123 nie oznacza więc 123 adresów wykonanych w teście. W śladzie loadera wykonano 109 różnych adresów instrukcji.

## Najważniejsze pliki

| Plik / katalog | Zawartość |
|---|---|
| `src/GAME.M65` | Główne źródło z makrami, etykietami i oryginalnymi adresami w komentarzach |
| `src/BOOT.M65` | Loader i zasoby pierwszej fazy |
| `src/GAMEFLAT.M65`, `src/BOOTFLAT.M65` | Równoważne wersje bez zwijania instrukcji w makra |
| `analysis/game_listing.txt`, `analysis/boot_listing.txt` | Listing: adres RAM, bajty maszynowe, mnemonik / dane |
| `analysis/*_symbols.tsv`, `*_xrefs.tsv` | Symbole i odwołania do kodu/danych |
| `analysis/*_smc.tsv`, `*_macros.tsv`, `*_map.tsv` | Samomodyfikacje, wystąpienia makr, mapa kod/dane z offsetami ATR |
| `native/*.LST` | Numerowany tekst ATASCII z końcem wiersza $9B; to nie są tokenizowane pliki SAVE |
| `native/parts/G00.LST`–`G11.LST` | 12 mniejszych modułów do osobnej asemblacji na stałe adresy |
| `src/parts/*.M65` | Czytelne odpowiedniki tych modułów w ASCII |
| `extracted/` | Oryginalne bloki binarne i trzy zasoby przenoszone pod ROM |
| `build/ZYBEX_REBUILT.ATR` | Odbudowany, binarnie identyczny dysk |
| `build/verification.json`, `build/selftest.txt` | Wyniki sprawdzenia odtwarzania i testów narzędzi |
| `tools/` | Samodzielne narzędzia Python; bez zewnętrznych bibliotek |
| `manifest.json` | Rozmiary, skróty SHA-256, sektory i rozmieszczenie obrazów |

## 1. Obraz dysku i fazy ładowania

Plik ma 92 176 bajtów: 16 bajtów nagłówka ATR i 720 sektorów po 128 bajtów. Numeracja sektorów w tym raporcie zaczyna się od 1.

| Sektory | Offset pierwszego bajtu w ATR | Rozmiar | Znaczenie |
|---|---:|---:|---|
| 1–25 | $00010 | 3 200 B | Boot ładowany do $0480–$10FF |
| 26–255 | $00C90 | 29 440 B | Same zera |
| 256–620 | $07F90 | 46 720 B | Gra ładowana do $0600–$BC7F |
| 621–720 | $13610 | 12 800 B | Same zera |

Nagłówek bootu podaje 25 sektorów, adres ładowania $0480 i inicjalizację $0488. Pod $0486 znajduje się krótkie `CLC / RTS`. Właściwa inicjalizacja sprawdza `PORTB`; gałąź ostrzegawcza poleca przytrzymanie OPTION i restart.

Loader najpierw zachowuje trzy zasoby w wysokim RAM:

| Źródło w obrazie bootu | Cel w RAM | Rozmiar | Interpretacja |
|---|---|---:|---|
| $0700–$0BFF | $E400–$E8FF | 1 280 B | Wzory znaków / grafika menu |
| $0C00–$0CFF | $FF00–$FFFF | 256 B | Mapa znaków z kafelków 2×2 |
| $0D00–$10FF | $DC00–$DFFF | 1 024 B | Zasób graficzny; pełna interpretacja nie jest potwierdzona |

Kopia czasowo ustawia `PORTB=$FE`, blokuje przerwania i po zakończeniu wraca do `PORTB=$FF`. To kopia zasobów gry, **nie kopia systemu operacyjnego**. Później gra wykorzystuje również RAM wektorów na końcu strony $FF.

`LOADPAYLOAD` pod $04EA odczytuje przez `JSR $E453` (DSKINV) sektory $0100–$026C, czyli 256–620. Docelowy bufor zaczyna się od $0600 i rośnie o $80. Po odczycie 365 sektorów loader ustawia DOSINI i przekazuje sterowanie pod **$0C80**. Główny blok nie przechodzi tu przez dekompresor.

Istotna jest kolejność: boot i gra częściowo zajmują te same adresy RAM w **różnych fazach**. `$0C80` w pliku bootu jest jeszcze danymi zasobu; po odczycie sektorów gry jest punktem wejścia programu. Nie można analizować obu obrazów jako jednego niezmiennego obszaru pamięci.

Dla głównego obrazu zachodzi:

```text
ATR_offset = $7F90 + (CPU_address - $0600)
           = CPU_address + $7990
```

## 2. Mapa najważniejszych procedur

| Adres | Proponowana etykieta | Zaobserwowana / wnioskowana rola |
|---|---|---|
| $0C80 | GAMEENTRY | Wejście po loaderze, inicjalizacja dźwięku i menu |
| $0D51 / $0D69 | STARTMUSIC / STOPMUSIC | Włączanie i zatrzymywanie muzyki |
| $0EC8 / $0F13 | MENUSTICK / MENUFIRE | Kierunki joysticka i przyciski fire w menu |
| $0F5F | STARTREQUEST | Obsługa żądania rozpoczęcia gry |
| $1000 | INITMENUNMI | Przejęcie wektorów NMI/IRQ, wyłączenie ROM |
| $102D / $1035 | MENUNMI / MENUVBI | Rozdział DLI/VBI i obsługa VBI menu |
| $107A | HISCOREENTRY | Tabela wyników / wprowadzanie inicjałów |
| $145C / $1483 | CLEARMENU / CLEARSCREENS | Czyszczenie obszarów ekranu przez kod samomodyfikujący |
| $150F | BUILDMENUDLIST | Budowanie listy ANTIC menu |
| $169D / $1709 | PRINT8X8 / PRINTBITMAP | Renderery tekstu |
| $173E | DRAWCHAR2X2 | Znaki składane z czterech kafelków |
| $1874 | INITGAME | Inicjalizacja rozgrywki / etapu |
| $197F | MAINLOOP | Główna pętla gry |
| $1DB5 | PRINTLEVELNAME | Wybór i wypisanie nazwy poziomu |
| $2416 / $24CD | UPDATEP1WEAPON / UPDATEP2WEAPON | Obsługa uzbrojenia graczy |
| $2630 | SETLEVELDATA | Instalacja kolorów i wskaźników danych poziomu |
| $2770 | PLAYERSVBI | Procedura obsługi graczy wywoływana z VBI |
| $37A3 | INITGAMENMI | Instalacja przerwań rozgrywki |
| $37DB / $37E3 | GAMENMI / GAMEVBI | Rozdział DLI/VBI i obsługa VBI gry |
| $39DD | SCROLLWORLD | Aktualizacja przewijania |
| $3A7A | DRAWNEXTMAPCOL | Przygotowanie kolejnej kolumny mapy |
| $3B3D | BLIT4ROWS | Zapis czterech wierszy z odstępem $2C |
| $3B6A | ADVANCEDLISTLMS | Modyfikacja 88 adresów LMS w liście ANTIC |
| $3B91 | WAITFRAMEFLIP | Synchronizacja z VBI i przełączaniem obrazu |
| $3ED4 / $4056 | SFX3TICK / SFX2TICK | Efekty na dwóch kanałach POKEY |
| $6A00 / $6A03 / $6A06 | MUSICINITVEC / MUSICSTOPVEC / MUSICVBI | Wejścia odtwarzacza muzyki |

Skrót przepływu sterowania:

```text
BOOTINIT -> COPYRESOURCES -> LOADPAYLOAD -> GAMEENTRY
                                             |
                                          menu / DLI / VBI
                                             |
                                       STARTREQUEST
                                             |
                                          INITGAME
                                             |
                                          MAINLOOP
                                  / synchronizacja i rysowanie
                                  / scrolling, obiekty, uzbrojenie
                                  / osobne NMI rozgrywki
```

Przykładowy fragment rzeczywistego listingu:

```asm
MAINLOOP
        INC LOOPCOUNT       ; $197F
        JSR WAITFRAMEFLIP   ; $1981
        JSR DRAWPOOL28      ; $1984
        JSR DRAWPLAYERPOOL  ; $1987
        JSR SCROLLWORLD     ; $198A
        JSR DRAWPOOL42      ; $198D
        JSR DRAWPOOL88      ; $1990
        JSR SUB30FC         ; $1993
        JSR SUB3301         ; $1996
        JSR SUB3301         ; $1999
```

Nazwy `SUB30FC` i `SUB3301` pozostają neutralne: adres i wywołania są ustalone, lecz pełna rola procedury nie jest potwierdzona. Powtórzonego wywołania `SUB3301` nie usunięto.

## 3. Dane i konwencje etykiet

`Lxxxx` to cel przepływu sterowania; `SUBxxxx` — procedura o ostrożnie pozostawionej nazwie; `Dxxxx` — dane; `SMxxxx` — instrukcja, do której bajtów istnieje odwołanie; `ZPxx` i `Mxxxx` — neutralne nazwy komórek. Nazwy takie jak `SCROLLWORLD` czy `MENUFIRE` są interpretacją funkcji. `ADRxxxx` to zdefiniowany z góry, stały adres dla parametrów makra.

Adresy współdzielone przez podsystemy nie dostają na siłę jednej semantyki. Przykładowo $95 i $9B są `TEXTCOL` / `TEXTROW` w rendererze tekstu, ale poza nim pozostają neutralnymi komórkami strony zerowej.

Uwzględniono różne znaczenie odczytu i zapisu rejestrów. W listingu odczyt $D010 nazywa się `TRIG0`, zapis pod ten adres — `GRAFP3`; odczyt $D40F to `NMIST`, zapis — `NMIRES`. Obszar obiektów $D800 jest RAM po wyłączeniu ROM, a nie rejestrem sprzętowym.

Pod $0600 rozpoznano 16 wskaźników zapisanych jako `.WORD`. Prowadzą do dziesięciobajtowych pól nazw poziomów zaczynających się od $0620: ARCTURUS, BEROS, CENTAURUS, RICTUS, SKORPIUS, TITAN, ANTARES, BAEUS, PROCYON, NECROS, ENCELADUS, DIABLOS, PYRIX, ZELAX, CYRUX i ZYBEX. Teksty korzystają z kodowania gry i terminatora $1A; nie przekodowano ich na inny format.

Wysoki RAM zawiera między innymi listy ANTIC pod $E200 i $E900, obszary obrazu od $C000 i $F000 oraz zasoby skopiowane przez boot. Dokładne granice aktywnych buforów zależą od fazy programu. Nie należy traktować całych stron z nazwami FRAMEBUFFER jako stale zajętych jednym typem danych.

## 4. Kod samomodyfikujący — zachowany bez zmian

Statycznie rozpoznano **126 instrukcji bezpośrednio zapisujących w kod gry**, obejmujących **80 różnych bajtów** należących do **57 instrukcji**. To wynik dla zapisów absolutnych widocznych w analizie, a nie dowód braku innych zapisów indeksowanych lub pośrednich.

Przykład $1466:

```asm
        LDA #$BC
        STA CLEARBCSTA+2
        LDY #$00
        TYA
CLEARBCSTA
        STA $FF00,Y
        DEY
        BNE CLEARBCSTA
        INC CLEARBCSTA+2
```

`$FF00` jest oryginalnym operandem instrukcji w pliku, a nie rzeczywistym początkowym celem czyszczenia po modyfikacji. Zapis do `CLEARBCSTA+2` ustawia starszy bajt adresu na $BC; kolejne iteracje zmieniają stronę.

Drugi przypadek dotyczy samego opcodu:

```text
$164F: EE 9D 3D   INC $3D9D
       CE 9D 3D   DEC $3D9D   po modyfikacji w czasie wykonania
```

Obie postacie zostały zaobserwowane w syntetycznym śladzie wykonania. Miejsca modyfikowane przez program pozostawiono jawnymi instrukcjami, nie ukryto ich w makrach. Nie wolno zmieniać długości tych sekwencji ani automatycznie przenosić procedur.

Pod $38E8 zachowano również nietypowy zapis obu składowych wskaźnika do $0129. Nie poprawiano go na $012A: bez szerszego potwierdzenia wykonania byłaby to zmiana oryginału oparta na przypuszczeniu.

## 5. Makra MAC/65

Makra zastępują **80 wystąpień**, reprezentujących 857 bajtów oryginalnego kodu. To uproszczenie źródła, nie kompresja ani zmniejszenie wynikowego programu.

| Makro | Liczba wystąpień łącznie | Działanie |
|---|---:|---|
| SETPTRXY | 40 | X=starszy bajt, Y=młodszy bajt; zapis wskaźnika w oryginalnej kolejności |
| SETWORD | 20 | Zapis stałego słowa przez akumulator, low potem high |
| WAITCLOCK | 7 | Oczekiwanie na konkretną wartość licznika modulo 256 |
| PUSHREGS | 4 | Zachowanie A, X, Y na stosie |
| POPREGS | 4 | Odtworzenie Y, X, A |
| COPYWORD | 3 | Kopia dwóch bajtów przez akumulator |
| SFXSTEP | 2 | Wspólny, 100-bajtowy algorytm dwóch głosów efektów |

Przykładowa definicja:

```asm
        .MACRO SETPTRXY
        LDX #>%2
        LDY #<%2
        STX %1+1
        STY %1
        .ENDM
```

To dokładnie cztery instrukcje oryginału: nie zastąpiono ich zapisem przez A, bo zmieniłoby to stan rejestrów i mogłoby zmienić działanie kodu wywołującego.

Większe powtórzenie jest używane następująco:

```asm
ADR4003 = $4003             ; SFX3STATE
ADR4185 = $4185             ; SFX2STATE

SFX3STEP
        SFXSTEP ADR4003,ZPFE,AUDF3  ; $3F2E-$3F91

; ... inne oryginalne instrukcje i dane ...

SFX2STEP
        SFXSTEP ADR4185,ZPFC,AUDF2  ; $40B0-$4113
```

Stałe `ADRxxxx` zapobiegają problemom z parametrami liczbowymi odnoszącymi się do jeszcze niezdefiniowanych etykiet w pierwszym przebiegu MAC/65. Etykiety lokalne wewnątrz makr są rozdzielane pomiędzy wystąpieniami. Generator nie zwija fragmentu, gdy istnieje wejście z zewnątrz do jego wnętrza albo rozpoznana samomodyfikacja jego bajtów. Każdy kandydat jest przed użyciem osobno asemblowany i porównywany z oryginałem.

## 6. Powtórzenie weryfikacji na komputerze

Wystarczy Python 3.10 lub nowszy; nie trzeba instalować pakietów z sieci. W katalogu pakietu:

```sh
python tools/rebuild.py
python tools/selftest.py
```

`rebuild.py` sprawdza trzy pełne warianty źródła bootu, trzy warianty gry oraz 24 warianty modułów (ASCII i ATASCII). Weryfikuje brak dziur i nakładania bajtów, zakresy gałęzi, oryginalne rozmiary i wynikowy ATR. Celowo odrzuca zmiany względem oryginału: jest narzędziem weryfikacji rekonstrukcji, nie narzędziem wydawania zmodyfikowanej gry.

Oczekiwany SHA-256 odbudowanego pliku:

```text
97f1aa6d09bbf6b772d8ce174a92f8b7870cfbd9efa148655af0b5557744fffe
```

Samodzielna asemblacja jednego źródła:

```sh
python tools/mac65_subset.py src/GAME.M65 -o build/GAME.bin
```

Powtórzenie analizy od wejściowego dysku, z katalogu pakietu:

```sh
python tools/extract.py "../Zybex (v1).atr"
python tools/trace_boot.py "../Zybex (v1).atr" --out analysis
python tools/trace_game.py analysis/ram_after_boot.bin --out analysis --steps 1000000
python tools/disassemble.py
python tools/split_native.py
python tools/rebuild.py
```

Ścieżkę do ATR należy dostosować do jego położenia. `extract.py` sprawdza skrót tej konkretnej wersji dysku. Etykiety i komentarze do dalszej pracy znajdują się w `tools/annotations.py`. Ponowne uruchomienie generatora nadpisze pliki `.M65`; trwałe zmiany opisu należy zatem wprowadzać w adnotacjach, a nie wyłącznie w wygenerowanym listingu.

## 7. Użycie oryginalnego MAC/65

Pliki `.M65` w `src/` to tekst ASCII do czytania i cross-assemblacji. Pliki `.LST` w `native/` to numerowany tekst ATASCII do komendy **ENTER**, nie pliki tokenizowane do LOAD czy bezpośredniego ASM z urządzenia. Pełny plik gry jest za duży na wygodne wczytanie w całości do edytora Atari; przygotowano dlatego osobne moduły.

Przykładowa procedura dla jednego modułu po umieszczeniu jego `.LST` na dysku dostępnym dla Atari:

```text
NEW
ENTER #D:G00.LST
ASM,#-,#D:G00.OBJ
```

Wyjście kierowane jest na dysk, nie do pamięci zajmowanej przez edytor/asembler. Wynik MAC/65 zawiera nagłówki segmentów; nie jest surowym blokiem, który można po prostu wkleić do ATR. Do binarnej rekonstrukcji w tym pakiecie służy `rebuild.py`. Nie należy też uruchamiać samego segmentu gry z pominięciem bootu i kopiowania zasobów.

Ta procedura została przygotowana według dokumentacji MAC/65, lecz nie wykonano jej w natywnym środowisku. Faktyczna ilość wolnej pamięci zależy od DOS i konfiguracji MAC/65; w razie potrzeby można wygenerować jeszcze mniejsze moduły przez `python tools/split_native.py --limit 2048`.

## 8. Co potwierdza test wykonania, a czego nie

Własny interpreter wykonał loader w 16 831 instrukcjach, zastępując DSKINV kontrolowanym odczytem dostarczonego ATR. Potwierdził wszystkie 365 odczytów, adresy docelowe oraz trzy kopie zasobów.

Drugi test wykonał **1 000 000 instrukcji**, osiągnął **3 607 różnych adresów instrukcji** i **62 razy wszedł do MAINLOOP**. Wszystkie osiągnięte adresy mieszczą się w statycznie rozpoznanym kodzie. Test podał 198 syntetycznych VBI i 581 DLI, symulował fire i neutralne kierunki joysticka. Potwierdził przejście od menu do rozgrywki oraz wybrane samomodyfikacje; nie zakończył się na nieznanym opcodzie ani BRK.

**Nie jest to test zgodności z prawdziwym Atari.** Nie ma renderowania ANTIC, DMA, rzeczywistego dźwięku POKEY, pełnego modelu ROM/bankowania, dokładnych cykli ani pełnej symulacji kolizji. Nie wykonano przejścia wszystkich poziomów, gry dwuosobowej ani pełnego testu tabeli wyników. Odtworzenie bajtów jest sprawdzone; kompletność semantyki i zachowania na sprzęcie pozostaje osobnym zagadnieniem.

Dołączone testy narzędzi obejmują 151 oficjalnych kodowań instrukcji, wyniki i przeniesienia ADC/SBC dla wszystkich poprawnych dwucyfrowych argumentów BCD, powrót z NMI, zawijanie strony przez pośredni JMP, etykiety makr i błędny zasięg gałęzi. To testy regresyjne, nie certyfikowany, niezależny zestaw zgodności procesora. Asembler i dezasembler współdzielą tabelę opcode'ów.

## 9. Dokumentacja odniesienia

Podstawą ustaleń dotyczących tej wersji gry są dostarczony ATR, listingi, mapy i ślady wykonania w tym pakiecie. Dokumentacja zewnętrzna służy do objaśniania składni i interfejsów platformy, nie jako źródło kodu gry.

- OSS / Stephen D. Lawrow, **MAC/65 Manual**, rozdziały 2–5 i 8, kopia HTML: https://mixinc.net/atari/mac65.htm
- **Atari Technical Reference, Resident Disk Handler**, DSKINV i DCB: https://www.atariarchives.org/cfn/05/07/0010.php
- **ATasm**, dokumentacja projektu kompatybilnego z MAC/65: https://github.com/CycoPH/atasm . ATasm nie był użyty do weryfikacji tego pakietu.
