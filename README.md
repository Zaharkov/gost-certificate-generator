# gost-certificate-generator
Есть один не очень маленький банк где нужны сертификаты по ГОСТ Р 34.11/34.10-2001<br/>
Можно костылить OpenSSL чтобы он мог генерить такие сертификаты<br/>
Можно купить крипто про (а точнее утилиту cryptcp), которая умеет в ГОСТ <br/>

А можно сделать это все через BouncyCastle =) <br/>
Собственно вот: <br/>
Генерация сертификата с нуля через BouncyCastle по ГОСТ Р 34.11/34.10-2001 <br/>
(NetCore 2.2, BouncyCastle.NetCore 1.8.5)

Если же нужен сертификат для ГОСТ 2012, то вам сюда  <br/>
https://github.com/Zaharkov/bc-csharp  <br/>
Нужны были изменения в основной репке BC чтобы заработало - генератор отдельным проектом  <br/>
