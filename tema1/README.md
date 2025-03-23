Tema 1: Cifrari Substituție și Transpunere
===========================================

Descriere:
----------
Această aplicație implementată în C oferă doi algoritmi clasici de cifrare:
1. Cifru de substituție:
   - Fiecare literă din textul simplu este înlocuită conform unei hărți predefinite.
   - Literele din afara alfabetului (de ex. cifre, semne de punctuație) rămân neschimbate.
2. Cifru de transpunere:
   - Se folosește o metodă de transpunere columnară.
   - Textul de intrare este plasat într-o matrice cu KEY_LENGTH = 4 coloane.
   - Dacă lungimea textului nu este un multiplu de 4, celulele libere se completează cu caracterul '_'.
   - Se citește matricea coloană cu coloană conform unei permutări predefinite (ordine: {1, 3, 2, 0}).

Aplicația acceptă operații de:
  - Criptare (-e)
  - Decriptare (-d)

Și permite alegerea algoritmului prin:
  - "-alg sub" pentru cifru de substituție 
  - "-alg trans" pentru cifru de transpunere

Instrucțiuni de compilare:
---------------------------
Pentru a compila aplicația, utilizați un compilator C (ex. gcc):

    gcc app.c -o app

Instrucțiuni de rulare:
-----------------------
Criptare cu cifru de substituție:
    ./app -e mesaj.txt -o criptat.txt -alg sub

Decriptare cu cifrul de substituție:
    ./app -d mesaj.txt -o criptat.txt -alg sub

Criptare cu cifrul de transpunere:
    ./app -e mesaj_criptat.txt -o mesaj_decriptat.txt -alg trans

Decriptare cu cifru de transpunere:
    ./app -d mesaj_criptat.txt -o mesaj_decriptat.txt -alg trans

Notă:
-----
- Dacă nu se specifică parametrul "-alg", se va folosi automat cifrul de substituție.
- Pentru cifrul de transpunere, dacă textul nu se potrivește exact în matrice, celulele rămase sunt completate cu caracterul '_'.

Testcases:
----------
1. Test pentru cifru de substituție:
   - Fișierul de intrare ("mesaj.txt"):
  
         Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
     
   - Rulați:
   
         ./app -e mesaj.txt -o criptat.txt -alg sub
     
   - Rezultatul din "criptat.txt" va fi:
   
         Sgktd ohlxd rgsgk loz qdtz, egflteztzxk qroholeofu tsoz, ltr rg toxldgr ztdhgk ofeororxfz xz sqwgkt tz rgsgkt dqufq qsojxq. Xz tfod qr dofod ctfoqd, jxol fglzkxr tbtkeozqzogf xssqdeg sqwgkol folo xz qsojxoh tb tq egddgrg egfltjxqz. Rxol qxzt okxkt rgsgk of kthktitfrtkoz of cgsxhzqzt ctsoz tllt eossxd rgsgkt tx yxuoqz fxssq hqkoqzxk. Tbethztxk lofz geeqteqz exhorqzqz fgf hkgortfz, lxfz of exshq jxo gyyoeoq rtltkxfz dgssoz qfod or tlz sqwgkxd.
         
   - Pentru decriptare, rulați:
   
         ./app -d criptat.txt -o decriptat.txt -alg sub
         
   - Fișierul "decriptat.txt" va conține textul original.

2. Test pentru cifru de transpunere:
   - Fișierul de intrare ("mesaj.txt"):
   
         Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
         
   - Rulați:
   
         ./app -e mesaj.txt -o criptat.txt -alg trans
         
   - Rezultatul din "criptat.txt" va fi:
   
            o uo  tocudsgisdioercd lrtl nlatidnvaq t ranlobsstip cocetua ro redt ute el oeutlpa.ces atptnpd,nnlqocdr la elr
            ep oim se pie,d s pidntb dra q e mmn,iouxiiumlrn aueamonu str onperiot iscuoe inaruEprncccdtnons caifasnotidtbm_rimlsa,ntric teoudm iuuae omai. m iemunrect a o i q eodoq.iuieliehe vpele ldrug lat euioe iaore t pufieuminisau
            Lmsdrtecetainl  emtonit oeoegauUnai i ssdetolcaiiulix m saD eudr rninlavtsiml fau irxt tcaua  ituiu  i etl m  o.
            
   - Pentru decriptare, rulați:
   
         ./app -d criptat.txt -o decriptat.txt -alg trans
         
   - Fișierul "decriptat.txt" va conține (la final fiind un caracter de umplere "_").

Abordare de implementare:
--------------------------
- **Cifru de substituție:** Se parcurge textul caracter cu caracter, iar pentru fiecare literă se înlocuiește folosind o hartă predefinită (QWERTY pentru majuscule și qwerty pentru minuscule). Pentru decriptare se efectuează operația inversă.
- **Cifru de transpunere:** Se implementează o metodă de transpunere columnară:
    1. Textul este plasat într-o matrice cu 4 coloane.
    2. Dacă este necesar, se completează cu caracterul '_'.
    3. Pentru criptare, se citește matricea coloană cu coloană conform unei permutări predefinite.
    4. Pentru decriptare, procesul se inversează.

