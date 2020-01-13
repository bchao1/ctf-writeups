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

## [crypto] RSACTR
這題是結合 RSA 和 block cipher counter mode 的加密，總共只能有三個 query。一開始有幾種想法：
### 想法一
傳 0 可以解出 nonce。傳一個 query 得到 flag 加密的結果，把結果 e 次方（三次方）以後可以列出一個 flag 的三次式 mod(n)。
   
下面都假設在解 flag 的第一個
block（同樣方法可以解另外兩個 block）。假設 flag 的**第一個 block** 是 F<sub>1</sub>。然後包含 nonce 的 counter 值是 C（這是可控的）。
- 我們拿到的密文是 (F<sub>1</sub> + C<sup>d</sup>) mod(n) = M<sub>1</sub>（往後省略 mod(n))。
-  三次方以後得到 (F<sub>1</sub> + C<sup>d</sup>)<sup>3</sup>
- 展開得 F<sub>1</sub><sup>3</sup> + F<sub>1</sub><sup>2</sup>C<sup>d</sup> +F<sub>1</sub>C<sup>2d</sup> + C<sup>3d</sup>
- 注意 C<sup>3d</sup>modn = C （由RSA定義）以及 C<sup>d</sup> = （M<sub>1</sub> - F<sub>1</sub>）modn。
- 化簡得 F<sub>1</sub><sup>3</sup> + F<sub>1</sub>C<sup>d</sup>(F<sub>1</sub>+C<sup>d</sup>) + C = F<sub>1</sub><sup>3</sup> + F<sub>1</sub>M<sub>1</sub>(M<sub>1</sub> - F<sub>1</sub>) + C = M<sub>1</sub><sup>3</sup>

由於 M<sub>1</sub>, C 都是已知，現在就是要解一個模n下的三次式。
### 想法二
> 稍微修改一下想法一

想法一只用到了兩次的 query，但題目給了三次，其實可以多用一次。所以最後一次 query 就再送一次 flag query，這時的 counter 變成上一個 query 的 counter + 6060 = C'。假設這次第一個 block 的密文是M<sub>2</sub>。
   
利用想法一的結果，可以列出
- F<sub>1</sub><sup>3</sup> + F<sub>1</sub>M<sub>1</sub>(M<sub>1</sub> - F<sub>1</sub>) + C
- F<sub>1</sub><sup>3</sup> + F<sub>1</sub>M<sub>2</sub>(M<sub>2</sub> - F<sub>1</sub>) + C'
- 相減得到 F<sub>1</sub>(M<sub>2</sub><sup>2</sup>-M<sub>1</sub><sup>2</sup>)+F<sub>1</sub><sup>2</sup>(M<sub>1</sub>-M<sub>2</sub>) + 6060 = M<sub>2</sub><sup>3</sup>-M<sub>1</sub><sup>3</sup>

這邊變成要解一個模n下的二次式。
   
因為要在模n下解，我就假設每個多項式除以n的商然後用sagemath去解爆搜，但都沒有做出合理的結果。

## [web] King of PHP

一開始看到原始碼大概知道可以用`c`來寫入檔案，並且可以透過傳`array`bypass strlen的檢查。用`f`可以任意讀檔，但flag不在根目錄下的/flag，因此覺得flag應該是執行擋，所以應該是要rce。

之後有查到 file_get_contents + phar 可以 rce，但是需要`__destruct` 或 `__wakeup` 等magic method 才能製造POP


https://blog.zsxsoft.com/post/38
https://ithelp.ithome.com.tw/articles/10204416
```php
strtolower($filename[0]) == "p" ? die("Bad 🍊!") : die(htmlspecialchars(file_get_contents($filename))); 
```
會檢查第一個字是不是p，所以`php://` `phar://`不能直接用，要用`compress.bzip2://`來bypass。

後來又找到他的php_info，用下面的工具

https://github.com/GoSecure/php7-opcache-override

算出他的system_id

```
PHP version : 7.4.3-dev
Zend Extension ID : API320190902,NTS
Zend Bin ID : BIN_48888
Assuming x86_64 architecture
------------
System ID : 418f4c6e5989490277b52c8b4023b08e
```


後來看到

https://eductf.zoolab.org:28443/?f=/usr/local/etc/php/conf.d/php-king.ini

裡面會用preload.php 去 preload opcache，可是php.ini裡面`opcache.file_cache`又是空白的，直接去訪問php opcache的預設路徑也真的找不到東西。

https://eductf.zoolab.org:28443/?f=tmp/opcache/418f4c6e5989490277b52c8b4023b08e/var/www/index.php.bin

原本想要利用`preload.php`裡的__detruct去串POP，因為裡面有

```php 
exec('rm' .$this->path)
```
只要能控path就能rce了，可是$path是private variable 沒辦法透過繼承去更動他，最後就卡在這裡....
