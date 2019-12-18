# watevr CTF 2019
## 隊名及組員
iAV1wKXhjxnPhg
- 李子筠
- 趙崇皓
- 陳昱行

## Scoreboard
總共 692 隊參加，最後我們的排名是 75，最高排名是 38。
![ranking](./img/scoreboard.png)

## 分工
我主要看 misc, web, forensics 和一點reverse，子筠研究 crypto 和 pwn，昱行看 web 和 reverse。我們找了一天學校家裡連線解題討論。

## 參與題目
|Problem|Category|Solved|
|---|---|---|
|Pickle Store|web|yes|
|Swedish State Service|web|yes|
|Super Sandbox|web|no|
|Evil Cuteness|forensics|yes|
|Blurry Image|forensics|no|
|Sanity Check|misc|yes|
|Unspaelleble|misc|yes|
|Polly|misc|no|

## Writeup
### Web - Pickle Store
> 題目說明：網頁會顯示你現在有 500 元，買到 1000 元的 pickle 就可以拿到 flag。
   
其實這次 ctf 還另外有一題 cookie store，然後就是改他的 cookie 就可以直接把自己的錢改很大去買 cookie 拿到 flag。這題叫做 pickle store，很明顯就是跟 pickle 有關。
   
一樣先去看瀏覽器裡面存的值，不過這時候只把 cookie base64 decode 也不會產生有意義的東西。這時把 decode 出來的東西 pickle.loads，就可以回復出一個 json 物件。
   
和 cookie store 不同的是，json 裡面多了一個 anti_tamper_hmac 的 field，去查了發現是個防止使用者隨便改值而隨機產生的 id。所以這題的解法沒有 cookie store 那麼水。
   
但其實他既然會用到 pickle，那就可以用 deserialization，所以我們就產生一個 reverse shell payload 然後 pickle.dumps，再塞回去瀏覽器的 cookie，很輕易的就拿到 reverse shell。

### Web - Swedish State Service
> 題目說明：給一個靜態網頁。

很自然的先去看看網頁的原始碼，發現他在 meta tag 裡面有一個路徑是 server.py，所以就直接去訪問那個路徑，沒想到就直接拿到了原始碼。
   
裡面用白名單檔 .gti 這個字串，所以明顯就是要我們去拿 .git。這時用 url 路徑去訪問 .git 裡面的資料也可以順利拿到，所以只要把
遠端的 .git 下載下來就可以試圖回覆之前的歷史。
   
我用 Scrabble (https://github.com/denny0223/scrabble) 幫我回復資料夾的內容後回到了把 flag.txt 移除的 commit，雙利拿到 flag。

### Web - Super Sandbox
> 題目說明：要求做到 alert(1) 後就可以拿到 flag。

去看了網站的原始碼發現裡面有個很像 jsfuck 的東西。
### Forensics - Evil Cuteness

### Forensics - Blurry Image
> 題目說明：給了一個很模糊的影像，還有一個原圖的 patch。

明顯就是利用原圖的那個 patch 還有模糊的 patch 來預測 convolution kernel，然後再試圖 deconvolve 回去。
   
我用 optimization 方法算出 blurring kernel （找到一個 kernel 使得原圖 patch 和 這個 kernel convolution 以後和模糊圖的 MSE 最小）。
   
拿到了 blurring kernel 以後，就要用這個 kernel 和模糊的圖回覆成原圖。這邊我試圖用 MATLAB, scipy 裡面的一些函式操作都沒有什麼結果。後來我想到可以對輸入的圖做 optimization，使得輸入圖和這個 kernel convolution 以後和模糊圖的 MSE 最小，但因爲時間不夠就沒有寫出來了。

### Misc - Sanity Check
去 Discord 上面翻一翻就找到 flag 了。

### Misc - Unspaelleble
> 題目說明：給了一個 4000 多行的劇本。

讀一讀幾行就會發現有幾個字拼錯。這時候我就去找到原本的 script 然後 diff 一下就拿到 flag 了。

### Misc - Polly
> 題目說明：給了一個係數很大的高次多項式。

觀察一下發現常數項是 119，是 w 的 ascii（比賽flag 型式是 watevr{}）。這時就猜帶入 0, 1, 2,3, 4,.... 就可以拿到 flag，但這邊就ㄧ直錯，卡了一下就先去做別題。
   
後來沒有解出來，在回顧的時候發現是 Python 數字大小還有浮點數的智障問題。我改用 sympy 就成功了。