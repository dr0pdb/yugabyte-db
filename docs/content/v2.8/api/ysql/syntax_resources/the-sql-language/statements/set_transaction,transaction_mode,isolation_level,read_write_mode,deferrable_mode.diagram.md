#### set_transaction

<svg class="rrdiagram" version="1.1" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns="http://www.w3.org/2000/svg" width="367" height="50" viewbox="0 0 367 50"><path class="connector" d="M0 37h15m43 0h10m106 0h30m-5 0q-5 0-5-5v-17q0-5 5-5h138q5 0 5 5v17q0 5-5 5m-5 0h35"/><polygon points="0,44 5,37 0,30" style="fill:black;stroke-width:0"/><rect class="literal" x="15" y="20" width="43" height="25" rx="7"/><text class="text" x="25" y="37">SET</text><rect class="literal" x="68" y="20" width="106" height="25" rx="7"/><text class="text" x="78" y="37">TRANSACTION</text><a xlink:href="#transaction-mode"><rect class="rule" x="204" y="20" width="128" height="25"/><text class="text" x="214" y="37">transaction_mode</text></a><polygon points="363,44 367,44 367,30 363,30" style="fill:black;stroke-width:0"/></svg>

#### transaction_mode

<svg class="rrdiagram" version="1.1" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns="http://www.w3.org/2000/svg" width="195" height="95" viewbox="0 0 195 95"><path class="connector" d="M0 22h35m104 0h41m-155 25q0 5 5 5h5m125 0h5q5 0 5-5m-150-25q5 0 5 5v50q0 5 5 5h5m120 0h10q5 0 5-5v-50q0-5 5-5m5 0h15"/><polygon points="0,29 5,22 0,15" style="fill:black;stroke-width:0"/><a xlink:href="#isolation-level"><rect class="rule" x="35" y="5" width="104" height="25"/><text class="text" x="45" y="22">isolation_level</text></a><a xlink:href="#read-write-mode"><rect class="rule" x="35" y="35" width="125" height="25"/><text class="text" x="45" y="52">read_write_mode</text></a><a xlink:href="#deferrable-mode"><rect class="rule" x="35" y="65" width="120" height="25"/><text class="text" x="45" y="82">deferrable_mode</text></a><polygon points="191,29 195,29 195,15 191,15" style="fill:black;stroke-width:0"/></svg>

#### isolation_level

<svg class="rrdiagram" version="1.1" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns="http://www.w3.org/2000/svg" width="409" height="125" viewbox="0 0 409 125"><path class="connector" d="M0 22h15m87 0h10m58 0h30m53 0h10m111 0h20m-204 25q0 5 5 5h5m53 0h10m93 0h23q5 0 5-5m-194 30q0 5 5 5h5m97 0h10m53 0h19q5 0 5-5m-199-55q5 0 5 5v80q0 5 5 5h5m108 0h71q5 0 5-5v-80q0-5 5-5m5 0h15"/><polygon points="0,29 5,22 0,15" style="fill:black;stroke-width:0"/><rect class="literal" x="15" y="5" width="87" height="25" rx="7"/><text class="text" x="25" y="22">ISOLATION</text><rect class="literal" x="112" y="5" width="58" height="25" rx="7"/><text class="text" x="122" y="22">LEVEL</text><rect class="literal" x="200" y="5" width="53" height="25" rx="7"/><text class="text" x="210" y="22">READ</text><rect class="literal" x="263" y="5" width="111" height="25" rx="7"/><text class="text" x="273" y="22">UNCOMMITTED</text><rect class="literal" x="200" y="35" width="53" height="25" rx="7"/><text class="text" x="210" y="52">READ</text><rect class="literal" x="263" y="35" width="93" height="25" rx="7"/><text class="text" x="273" y="52">COMMITTED</text><rect class="literal" x="200" y="65" width="97" height="25" rx="7"/><text class="text" x="210" y="82">REPEATABLE</text><rect class="literal" x="307" y="65" width="53" height="25" rx="7"/><text class="text" x="317" y="82">READ</text><rect class="literal" x="200" y="95" width="108" height="25" rx="7"/><text class="text" x="210" y="112">SERIALIZABLE</text><polygon points="405,29 409,29 409,15 405,15" style="fill:black;stroke-width:0"/></svg>

#### read_write_mode

<svg class="rrdiagram" version="1.1" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns="http://www.w3.org/2000/svg" width="193" height="65" viewbox="0 0 193 65"><path class="connector" d="M0 22h35m53 0h10m52 0h28m-158 0q5 0 5 5v20q0 5 5 5h5m53 0h10m60 0h5q5 0 5-5v-20q0-5 5-5m5 0h15"/><polygon points="0,29 5,22 0,15" style="fill:black;stroke-width:0"/><rect class="literal" x="35" y="5" width="53" height="25" rx="7"/><text class="text" x="45" y="22">READ</text><rect class="literal" x="98" y="5" width="52" height="25" rx="7"/><text class="text" x="108" y="22">ONLY</text><rect class="literal" x="35" y="35" width="53" height="25" rx="7"/><text class="text" x="45" y="52">READ</text><rect class="literal" x="98" y="35" width="60" height="25" rx="7"/><text class="text" x="108" y="52">WRITE</text><polygon points="189,29 193,29 193,15 189,15" style="fill:black;stroke-width:0"/></svg>

#### deferrable_mode

<svg class="rrdiagram" version="1.1" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns="http://www.w3.org/2000/svg" width="224" height="50" viewbox="0 0 224 50"><path class="connector" d="M0 22h35m45 0h20m-80 0q5 0 5 5v8q0 5 5 5h55q5 0 5-5v-8q0-5 5-5m5 0h10m99 0h15"/><polygon points="0,29 5,22 0,15" style="fill:black;stroke-width:0"/><rect class="literal" x="35" y="5" width="45" height="25" rx="7"/><text class="text" x="45" y="22">NOT</text><rect class="literal" x="110" y="5" width="99" height="25" rx="7"/><text class="text" x="120" y="22">DEFERRABLE</text><polygon points="220,29 224,29 224,15 220,15" style="fill:black;stroke-width:0"/></svg>
