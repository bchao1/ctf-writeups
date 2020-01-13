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

這題只拿到一個程式執行的 trace log，分析一下以後發現是 golang 的（知道這個其實沒用）。整個 trace 很長，但其實有很多是 library function 或各種 system function 不重要，把這些東西忽略以後，先去搜索整個 trace 裡面 `Pokemon` 一開始出現在：
```
Entering main.main at /home/terrynini38514/Desktop/PokemonV2.go:38:6.
.0:
	 t0 = new string (input)
```
看起來 t0 是一個輸入。接著進入 golang 的
 scanf 函式（不重要），然後回到 `Pokemon`：
 ```
 Leaving fmt.Scanf, resuming main.main at /home/terrynini38514/Desktop/PokemonV2.go:40:14.
	 t6 = *t0
	 t7 = PikaCheck(t6)
Entering main.PikaCheck at /home/terrynini38514/Desktop/PokemonV2.go:6:6.
```
這邊很就很明顯了，PikaCheck 應該是去檢查我們的輸入是否符合條件（也就是 flag）。PikaCheck 一開始初始化一個陣列：
```
.0:
	 t0 = local [20]int (a)
	 jump 3
```
接著就是迴圈判斷（for loop)：
```
.3:
	 t92 = phi [0: 0:int, 1: t10] #i
	 t93 = len(input)
	 t94 = t92 < t93
	 if t94 goto 1 else 2
```
迴圈本體是：
```
.1:
	 t1 = &t0[t92]
	 t2 = input[t92]
	 t3 = convert int <- uint8 (t2)
	 t4 = t92 + 1:int
	 t5 = len(input)
	 t6 = t4 % t5
	 t7 = input[t6]
	 t8 = convert int <- uint8 (t7)
	 t9 = t3 + t8
	 *t1 = t9
	 t10 = t92 + 1:int
	 jump 3
```
這邊很明顯是把輸入的第 i 和 第 i+1 個字元加起來存入 t0[i]。
   
這個迴圈執行完以後，就會進入下一步的檢查（下面是一組，總共有 20 組）：
```
t11 = &t0[0:int]
t12 = *t11
t13 = t12 - 185:int
t14 = 0:int + t13
...
```
這邊就是檢查 t0 裡面的每一個值。

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

## [web] babyRMI
從原始碼看起來 remote 端會有一個 registry，裡面會放一些 RMIInterface 的物件。每個物件有一些函式可以呼叫。執行 compile.sh 就可以執行 runClient.sh，就是去執行 Client.java 的內容。
   
我們發現 Client.java 是呼叫 sayHello()，接下來就嘗試呼叫 getSecret()，他說
```
response: Hint: FLAG is not in this object! Try to find another object :)
```
所以很明顯就是要找其他的 RMIInterface。這邊就將 registry 裡的東西列出來：
```java
String[] boundNames = registry.list();
for (String name : boundNames) {
    System.out.println(name);
}
```
```
FLAG
Hello
```
然後修改一下 Client.java
```java
RMIInterface stub = (RMIInterface) registry.lookup("Hello");
String response = stub.getSecret();
```
就可以拿到 flag。