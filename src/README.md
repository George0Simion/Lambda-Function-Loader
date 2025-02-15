<p align="center">
  <a href="" rel="noopener">
 <img src="https://i.imgur.com/AZ2iWek.png" alt="Project logo"></a>
</p>
<h3 align="center">Project Title</h3>

<div align="center">

</div>

---

<p align="center"> Autori: Buzatu Calin - Cristian, Simion George - Constantin
    <br> 
</p>

## 📝 Table of Contents

- [Problem Statement](#problem_statement)
- [Idea / Solution](#idea)
- [Dependencies / Limitations](#aditional)
- [Future Scope](#future_scope)

## 🧐 Lambda Function Loader <a name = "problem_statement"></a>

Acest proiect s-a rezumat la crearea unui sistem capabil sa incarce librarii dinamice si sa execute functii pe un serfver folosindu-se de modelul client - server. Clientii pot incarca si executa functii care sunt pre-implementate in librarii dinamice. Serverul contine deasemenea o limitare a resurselor pentru fiecare client, o alarma pentru fiecare proces care dureaza prea mult . Serverul beneficeaza de asemenea de 0 memory leakuri.

## 💡 Idea / Solution <a name = "idea"></a>

Serverul este implementat prin UNIX_SOCKET-uri. Initial, am creat socket-ul, l-am adaugat in familia AF_UNIX, am salvat socket-ul dat de cerinta, i-am dat bind si am inceput ascultarea pe acesta. Intr-un while "infinit", acceptam fiecare client si cream un proces nou pentru acesta. In fiecare proces serverul primeste mesajul de la client, aloca memoria necesara, parseaza mesajul, porneste procesarea librariei dinamice si la final trimite output-ul functiei executate pe server. Pentru fiecare librarie primita, prima data o deschidem, dupa aceea cautam cautam comanda in librarie. In continuare, cream o copie a output-ului dupa template-ul dat si setam file descriptorii. Apoi, rulam comanda specifica, cu parametrii sau nu, intr-un proces separat. Acesta metoda garanteaza siguranta ca comanda este executata cu bine indiferent daca aceasta are probleme sau nu (ex. segfault). La final restauram file descriptor-ul de out. Pentru error handling, folosim o functie separata care scrie output-ul dorit in functie de comanda. 

## 💡 Additional Tasks <a name = "aditional"></a>

Pe langa cerinta data, am implementat un sistem de alarma care ucide procesul in momentul in care dureaza prea mult. Acesta functionalitatea ofera un nivel de securitate a serverului, ucigand un proces in caz ca face ceva malicious. Deasemenea, am adaugat o functie limitare pe proces, salvand din resursele serverului pentru o durata de viata mai lunga.

## 🚀 Future Scope <a name = "future_scope"></a>

Am incercat integrarea unui sistem de logging, insa din cauza crizei de timp nu am apucat sa-l ducem la capat / rezolvam toate bug-urile. Insa, codul este inclus in proiect in folder-ul Extra pentru un viitor development.

