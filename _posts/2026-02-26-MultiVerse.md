---
title: MultiVerse
date: 2026-02-26 12:00:00
categories: [CTF, OSINT]
tags: [writeup, 0xfun]
---

## Сhallenge Info
* Platform: 0xfun
* Category: OSINT
* Diffuculty: medium
* Points: 250

## Challenge Description
I have a friend named Massive-Equipment393 who’s obsessed with music. Try to figure out what his favorite genre is.

## Solution
I started by searching nickname on google
> https://www.google.com/search?q=Massive-Equipment393

And found a Reddit account:
> https://www.reddit.com/user/Massive-Equipment393/

<img width="2250" height="1115" alt="image" src="https://github.com/user-attachments/assets/adacdffe-9810-4a46-a2d8-06d09a40c22a" />
The post on r/CTFlearn is quite interesting:
<img width="1505" height="322" alt="image" src="https://github.com/user-attachments/assets/d3ccb26b-6fdd-4981-a0d1-751a9f4ab477" />

```
all 49Rak48kGp7nJoUq9ofCX everyday.
```
Decrypting from base58 gives us part of a flag:
```
“pl4yl1st_3xt3nd”
```
Then I went to his spotify:
> https://open.spotify.com/user/3164whos3zc5xss6lv7ejfdlmogi

<img width="1759" height="1239" alt="image" src="https://github.com/user-attachments/assets/25350151-148c-40b0-800a-650faa9f1bdb" />
It has 3 playlists, let’s go through all of them:

<img width="2030" height="1237" alt="image" src="https://github.com/user-attachments/assets/7f73504c-e435-4b42-84a3-1b6049c3004e" />
<img width="1830" height="1014" alt="image" src="https://github.com/user-attachments/assets/32f3cffe-9c41-4af5-98f3-d9c303835f3f" />
<img width="1834" height="961" alt="image" src="https://github.com/user-attachments/assets/4ab55358-a996-4e67-9932-7763d3838594" />

In the descrription of the 3rd playlist we can see base64d part of a flag, let's decrypt it:
```
0xfun{sp0t1fy_
```
That looks like a first part of a flag, by far we have:
```
0xfun{sp0t1fy_pl4yl1st}
```
But when I tried to submit it it said it was wrong, so there must be more to the flag.

I quickly went through all playlist and only one of them had songs, but some of them were repeated too.

I copied first symbols of all songs and got 3rd part of the flag:

<img width="2030" height="1237" alt="image" src="https://github.com/user-attachments/assets/56ce9f0f-2fb9-4f00-b5d9-ad6cc1d41d70" />

## Flag
The final flag:
```
0xfun{sp0t1fy_pl4yl1st_3xt3nd_M0R3_TR4X}
```
