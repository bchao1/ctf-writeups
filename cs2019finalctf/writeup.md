# Computer Security 2019 Final CTF 
## 隊名與組員
> NTUQQ
- 電機三趙崇皓
- 電機三李子筠
- 電機三陳昱行
- 資工三李豈翔
## 解題統計
|Category|Solves|
|---|---|
|pwn|1|
|reverse|3|
|web|1|
|crypto|0|
|misc|2|
|Total|7|

## 解題流程
### [Reverse] PokemonGo

### [pwn] Impossible
這題基本上是要 bypass 長度的限制。注意到當長度輸入是負的，程式是用 `len = abs(len)` 的方式來修正。這邊很自然會想到利用 int 的邊界條件。
   
```c
len = -2,147,483,648;
...
len = abs(len); // len is still -2,147,483,648 due to overflow
...
read( 0 , buf , len ); // len interpreted as size_t 
```
如上所示，如果我們將 `len` 設為 int 最小值，就可以繞過長度大小檢查，再利用 read 會 implicit cast 的特性，就可以達到 bof。
   
知道可以 bof 以後，接下來就簡單了。因為這題 PIE 沒有開，所以可以輕易訪問 .plt 和 .got。這邊串個 ROP chain 先讀 puts@got 拿到 puts 的 libc，然後算出 libc base。接著回到 main。第一次 ROP 如下：
```
pop_rdi, ret
puts@got address
puts@plt
main // 跳回 plt 再 ROP 一次
```
現在拿到了 libc base，就可以輕易拿到 system address，所以這邊就再 rop 一次：
```
ret // alignment 的問題
pop_rdi, ret
bin_sh libc address 
system libc address
```
執行完就成功拿 shell。