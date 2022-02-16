#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#define rozmiar 1000
#define rozmiar_hasla 33

char *rozkodowaneHasla=NULL;                    // Wskaznik na rozkodowane hasla
char *rozkodowaneHaslaMD5=NULL;                 // Wskaznik na rozkodowane hasla
int indeksZdekodowanegoHasla;                   // Numer zdekowodanego hasla z tablicy hasel hasz
int iloscRozkodowanych=0;                       // Koncowa ilosc rozkodownych hasel
pthread_mutex_t mutex;                          // Zmienna odpowiadajaca za mutex
pid_t pid;                                      // PID procesu, potrzebne do zakonczenia programu
char zakodowaneHasla[rozmiar][rozmiar_hasla];   // 1000 zakodowanych hasel o dlugosci 33




// Struktura slownika
struct Struktura_SLOWNIK
{
  char **SLOWNIK;            // slowa
  int dlugoscSLOWNIK;        // Ilosc słow
};







// Signal handler, uzywany do wylapania sygnalu SIGHUP i wyjscia z programu
void sig_handler(int signum)
{
  printf("Rozkodowanych hasel: %d\n",iloscRozkodowanych);
  exit(1);
}







// Zamiana MD5 na hexadecymalny MD5
void MD5_na_MD5hex(char* MD5, char* MD5hex)
{
  int j = 0;
  int i = 0;

  while(MD5[j]!='\0')
  {
    sprintf((char*)(MD5hex+i),"%02hhx", MD5[j]);
    j+=1;
    i+=2;
  }
  MD5hex[i++] = '\0';
}







// Porownuje kod MD5 hasla wygenerowanego za pomoca slownika, z kodem MD5 z tablicy hasel
void porownajHasla (char *hexadecimalMD5k, char *haslo_1, int i)
{
	if(zakodowaneHasla[i][0] != '*')                                                      // Jesli nie oznaczone jako rozkodowane
	{
	  if(strcmp(zakodowaneHasla[i], hexadecimalMD5k) == 0 && strlen(hexadecimalMD5k) > 0) // Jesli uda się pozytywnie przyrownac hasla
    {
      pthread_mutex_lock(&mutex);                                           // Startujemy mutex
      rozkodowaneHaslaMD5 = (char*)malloc((strlen(hexadecimalMD5k+1))*sizeof(char));
      rozkodowaneHasla = (char*)malloc((strlen(haslo_1+1))*sizeof(char));   // Dopisujemy haslo do rozkodowanych
      strcpy(rozkodowaneHasla, haslo_1);
      strcpy(rozkodowaneHaslaMD5, hexadecimalMD5k);
      indeksZdekodowanegoHasla=i;
      pthread_mutex_unlock(&mutex);                                         // Konczymy mutex
    }
  }
}









int dodajLiczby (char *haslo_1, char *haslo_2, int dlugoscSlowa, int iloscNumerow)
{
  // z tylu
  if(haslo_1[dlugoscSlowa+iloscNumerow-1]<'9')    // Gdy na koncu nie ma 9
	{
	  haslo_1[dlugoscSlowa+iloscNumerow-1]++;       // Zwieksz cyfre
	}
	else                                            // Gdy na koncu jest 9
	{
	  haslo_1[dlugoscSlowa+iloscNumerow-1]='0';     // Zamien ostatnia cyfre na 0
	  int i=dlugoscSlowa+iloscNumerow-2;            // Przejdz na kolejna cyfre
	  while(haslo_1[i]=='9')                        // Dopoki cyfra to 9
    {
	    haslo_1[i]='0';                             // Zamien ja na 0
	    i--;                                        // Przejdz na kolejna cyfre
	  }
	  if(i<dlugoscSlowa)                            // Jesli sa same 9
	  {
	    return 1;                                   // Zwroc 1 (potrzebne w producencie)
    }
    else
    {
	    haslo_1[i]++;                               // Zwieksz cyfre jesli nie jest 9
	  }
	}



  // z przodu
	if(haslo_2[iloscNumerow-1]<'9')                 // Gdy na poczatku nie ma 9
  {
    haslo_2[iloscNumerow-1]++;                    // Zwieksz cyfre
  }
  else                                            // Gdy na poczatku jest 9
  {
    haslo_2[iloscNumerow-1]='0';                  // Zamien na 0
	  int i=iloscNumerow-2;                         // Przejdz na kolejna cyfre
    while(haslo_2[i]=='9' && i>0)                 // Dopoki cyfra to 9
    {
      haslo_2[i]='0';                             // Zamien ja na 0
      i--;                                        // Przejdz na kolejna cyfre
    }
    if(i<0)                                       // Jesli sa same 9
    {
      return 1;                                   // Zwroc 1 (potrzebne w producencie)
    }
    else
    {
      haslo_2[i]++;                               // Zwieksz cyfre jesli nie jest 9
    }
  }
  
  return 0;
}









// Producent 0: wszystko malymi literami, cyfry z przodu/tylu
void *Producent_0(void *Slownik_Argument)
{
  struct Struktura_SLOWNIK *args = (struct Struktura_SLOWNIK*)Slownik_Argument;
  int iloscNumerow=0; // Liczba numerow dopisanych na koncu/poczatku hasla
  int dlugoscSlowa=0; // Dlugosc slowa ze slownika
  char *haslo_1;      // Wygenerowane haslo liczby z tylu
  char *haslo_2;      // Wygenerowane haslo liczby z przodu
  char MD5hex_1[33];  // MD5 hexadecymalny liczby z tylu
  char MD5hex_2[33];  // MD5 hexadecymalny liczby z przodu
  char hash_1[17];    // Hash hasla liczby z tylu
  char hash_2[17];    // Hash hasla liczby z przodu
  hash_1[16] = '\0';
  hash_2[16] = '\0';


  while(1)
  {
    for (int i=0; i < args->dlugoscSLOWNIK; i++)      // Bierzemy kaze slowo po kolei
    {
      dlugoscSlowa = 0;                               // Zeruje dlugosc slowa
      while (args->SLOWNIK[i][dlugoscSlowa]!='\0')    // Odczyuje dlugosc slowa
      {
        dlugoscSlowa++;
      }

      // Alokacja pamieci na hasla z dodanymi cyframi
      haslo_1 = (char*)malloc(sizeof(char)*(dlugoscSlowa + iloscNumerow + 1));
      haslo_2 = (char*)malloc(sizeof(char)*(dlugoscSlowa + iloscNumerow + 1));

      // Bierzemy haslo
      strcpy(haslo_1,args->SLOWNIK[i]);

      // Producent 0 - zmniejszanie wszystkich znakow, gdyby w slowniku byly wielkie litery
      for(int j=0;j<dlugoscSlowa;j++)
      {
	      if(haslo_1[j]>64 && haslo_1[j]<91) // Operujemy na kodzie ASCII
        {
         	haslo_1[j]+=32;
        }
      }
      haslo_1[dlugoscSlowa] = '\0';        // Dodajemy znacznik końca stringa
      haslo_2[0] = '\0';

      // Dodajemy 0 na koncu wyrazow tyle ile ma byc numerow
      for (int j=0; j < iloscNumerow; j++)
      {
       	strcat(haslo_1, "0");
        strcat(haslo_2, "0");
      }

      // Doklejenie haslo_1 do haslo_2, aby w haslo_2 miec cyfry na poczatku
      strncat(haslo_2, haslo_1, dlugoscSlowa);

      // MD5
      MD5(haslo_1, strlen(haslo_1)*sizeof(char), hash_1);     // Zamiana hasla liczby z tylu na MD5
      MD5(haslo_2, strlen(haslo_2)*sizeof(char), hash_2);     // Zamiana hasla liczby z przodu na MD5
      hash_1[16] = '\0';
      MD5_na_MD5hex(hash_1, MD5hex_1);                        // Zamiana MD5_1 na MD5hex_1
      hash_2[16] = '\0';
      MD5_na_MD5hex(hash_2, MD5hex_2);                        // Zamiana MD5_2 na MD5hex_2

      // Sprawdzenie hasel wygenerowanych i zamienionych na MD5
      for(int i=0;i<rozmiar;i++)
      {
        porownajHasla(MD5hex_1, haslo_1, i);                  // Porownanie hasla liczby z tylu
        porownajHasla(MD5hex_2, haslo_2, i);                  // Porownanie hasla liczby z przodu
      }

      int out=0;                                              // Zmienna pomocnicza do wyjscia z petli

      while(!out)
      {
        // Funkcja generujaca liczby z przodu i z tylu hasla
  	    out = dodajLiczby(haslo_1, haslo_2, dlugoscSlowa, iloscNumerow);  // po to return 1 

	      if(!out)
	      {
	        // MD5 DLA LICZB
          MD5(haslo_1, strlen(haslo_1)*sizeof(char), hash_1); // Zamiana hasla liczby z tylu na MD5
          MD5(haslo_2, strlen(haslo_2)*sizeof(char), hash_2); // Zamiana hasla liczby z przodu na MD5
          hash_1[16] = '\0';
          MD5_na_MD5hex(hash_1, MD5hex_1);                    // Zamiana MD5_1 na MD5hex_1
          hash_2[16] = '\0';
          MD5_na_MD5hex(hash_2, MD5hex_2);                    // Zamiana MD5_2 na MD5hex_2

          // Sprawdzenie hasel wygenerowanych i zamienionych na MD5
          for(int i=0;i<rozmiar;i++)
          {
            porownajHasla(MD5hex_1, haslo_1, i);
            porownajHasla(MD5hex_2, haslo_2, i);
          }
	      }
      }
    }
    iloscNumerow++;             // Dodanie kolejnego numeru z przodu/tylu hasla
  }

  // Uwalnianie pamieci
  pthread_mutex_lock(&mutex);    // Startujemy mutex
  free(haslo_1);
  free(haslo_2);
  pthread_mutex_unlock(&mutex);  // Konczymy mutex
}


















// Producent 1: pierwsza litera wielka, reszta male cyfry z przodu/tylu
void *Producent_1(void *Slownik_Argument)
{
  struct Struktura_SLOWNIK *args = (struct Struktura_SLOWNIK*)Slownik_Argument;
  int iloscNumerow=0; // Liczba numerow dopisanych na koncu/poczatku hasla
  int dlugoscSlowa=0; // Dlugosc slowa ze slownika (hasla)
  char *haslo_1;      // Wygenerowane haslo liczby z tylu
  char *haslo_2;      // Wygenerowane haslo liczby z przodu
  char MD5hex_1[33];  // MD5 hexadecymalny liczby z tylu
  char MD5hex_2[33];  // MD5 hexadecymalny liczby z przodu
  char hash_1[17];    // Hash hasla liczby z tylu
  char hash_2[17];    // Hash hasla liczby z przodu
  hash_1[16] = '\0';
  hash_2[16] = '\0';

  while(1)
  {
    for (int i=0; i < args->dlugoscSLOWNIK; i++)      // Bierzemy kaze slowo po kolei
    {
      dlugoscSlowa = 0;                               // Zeruje dlugosc slowa
      while (args->SLOWNIK[i][dlugoscSlowa]!='\0')    // Odczyuje dlugosc slowa
      {
        dlugoscSlowa++;
      }

      // Alokacja pamieci na hasla z dodanymi cyframi
      haslo_1 = (char*)malloc(sizeof(char)*(dlugoscSlowa + iloscNumerow + 1));
      haslo_2 = (char*)malloc(sizeof(char)*(dlugoscSlowa + iloscNumerow + 1));

      // Bierzemy haslo
      strcpy(haslo_1,args->SLOWNIK[i]);

      // Producent 1: Zwiekszenie pierwszego znaku
      if(haslo_1[0] > 96 && haslo_1[0] < 123) // Operujemy na kodzie ASCII
      {
       	haslo_1[0]-=32;
      }

      // Producent 1: Zmniejszanie wszystkich znakow opróc pierwszego
      for(int j=1 ; j < dlugoscSlowa ; j++)
      {
        if(haslo_1[j] > 64 && haslo_1[j] < 91) // Operujemy na kodzie ASCII
        {
          haslo_1[j]+=32;
        }
      }
      haslo_1[dlugoscSlowa] = '\0';            // Dodajemy znacznik końca stringa
      haslo_2[0] = '\0';

      // Dodajemy 0 na koncu wyrazow tyle ile ma byc numerow
      for (int j=0; j < iloscNumerow; j++)
      {
       	strcat(haslo_1, "0");
        strcat(haslo_2, "0");
      }

      // Doklejenie haslo_1 do haslo_2, aby w haslo_2 miec cyfry na poczatku
      strncat(haslo_2,haslo_1,dlugoscSlowa);

      // MD5
      MD5(haslo_1, strlen(haslo_1)*sizeof(char), hash_1);     // Zamiana hasla liczby z tylu na MD5
      MD5(haslo_2, strlen(haslo_2)*sizeof(char), hash_2);     // Zamiana hasla liczby z przodu na MD5
      hash_1[16] = '\0';
      MD5_na_MD5hex(hash_1, MD5hex_1);                        // Zamiana MD5_1 na MD5hex_1
      hash_2[16] = '\0';
      MD5_na_MD5hex(hash_2, MD5hex_2);                        // Zamiana MD5_2 na MD5hex_2

      // Sprawdzenie hasel wygenerowanych i zamienionych na MD5
      for(int i=0;i<rozmiar;i++)
      {
        porownajHasla(MD5hex_1, haslo_1, i);                  // Porownanie hasla liczby z tylu
        porownajHasla(MD5hex_2, haslo_2, i);                  // Porownanie hasla liczby z przodu
      }

      int out=0;                                              // Zmienna pomocnicza do wyjscia z petli

      while(!out)
      {
        // Funkcja generujaca liczby z przodu i z tylu hasla
  	    out = dodajLiczby(haslo_1, haslo_2, dlugoscSlowa, iloscNumerow);

	      if(!out)
	      {
	        // MD5 DLA LICZB
          MD5(haslo_1, strlen(haslo_1)*sizeof(char), hash_1); // Zamiana hasla liczby z tylu na MD5
          MD5(haslo_2, strlen(haslo_2)*sizeof(char), hash_2); // Zamiana hasla liczby z przodu na MD5
          hash_1[16] = '\0';
          MD5_na_MD5hex(hash_1, MD5hex_1);                    // Zamiana MD5_1 na MD5hex_1
          hash_2[16] = '\0';
          MD5_na_MD5hex(hash_2, MD5hex_2);                    // Zamiana MD5_2 na MD5hex_2

          // Sprawdzenie hasel wygenerowanych i zamienionych na MD5 lista hasel MD5
          for(int i=0;i<rozmiar;i++)
          {
            porownajHasla(MD5hex_1, haslo_1, i);
            porownajHasla(MD5hex_2, haslo_2, i);
          }
	      }
      }
    }
    iloscNumerow++;                                           // Dodanie kolejnego numeru z przodu/tylu hasla
  }

  // Uwalnianie pamieci
  pthread_mutex_lock(&mutex);    // Startujemy mutex
  free(haslo_1);
  free(haslo_2);
  pthread_mutex_unlock(&mutex);  // Konczymy mutex
}



















// Producent 2: Wszystkie litery wielkie, cyfry z przodu/tylu
void *Producent_2(void *Slownik_Argument)
{
  struct Struktura_SLOWNIK *args = (struct Struktura_SLOWNIK*)Slownik_Argument;
  int iloscNumerow=0; // Liczba numerow dopisanych na koncu/poczatku hasla
  int dlugoscSlowa=0; // Dlugosc slowa ze slownika (hasla)
  char *haslo_1;      // Wygenerowane haslo liczby z tylu
  char *haslo_2;      // Wygenerowane haslo liczby z przodu
  char MD5hex_1[33];  // MD5 hexadecymalny liczby z tylu
  char MD5hex_2[33];  // MD5 hexadecymalny liczby z przodu
  char hash_1[17];    // Hash hasla liczby z tylu
  char hash_2[17];    // Hash hasla liczby z przodu
  hash_1[16] = '\0';
  hash_2[16] = '\0';

  while(1)
  {
    for (int i=0; i < args->dlugoscSLOWNIK; i++)      // Bierzemy kaze slowo po kolei
    {
      dlugoscSlowa = 0;                               // Zeruje dlugosc slowa
      while (args->SLOWNIK[i][dlugoscSlowa]!='\0')    // Odczyuje dlugosc slowa
      {
        dlugoscSlowa++;
      }

      // Alokacja pamieci na hasla z dodanymi cyframi
      haslo_1 = (char*)malloc(sizeof(char)*(dlugoscSlowa + iloscNumerow + 1));
      haslo_2 = (char*)malloc(sizeof(char)*(dlugoscSlowa + iloscNumerow + 1));

      // Bierzemy haslo
      strcpy(haslo_1,args->SLOWNIK[i]);

      // Producent 2 - zwiekszanie wszystkich znakow
      for(int j=0 ; j < dlugoscSlowa ; j++)
      {
	     if(haslo_1[j] > 96 && haslo_1[j] < 123) // Operujemy na kodzie ASCII
        {
         	haslo_1[j]-=32;
        }
      }
      haslo_1[dlugoscSlowa] = '\0';     // Dodajemy znacznik końca stringa
      haslo_2[0] = '\0';

      // Dodajemy 0 na koncu wyrazow tyle ile ma byc numerow na koncu
      for (int j=0; j < iloscNumerow; j++)
      {
       	strcat(haslo_1, "0");
        strcat(haslo_2, "0");
      }

      // Doklejenie haslo_1 do haslo_2, aby w haslo_2 miec cyfry na poczatku
      strncat(haslo_2, haslo_1, dlugoscSlowa);

      // MD5
      MD5(haslo_1, strlen(haslo_1)*sizeof(char), hash_1);     // Zamiana hasla liczby z tylu na MD5
      MD5(haslo_2, strlen(haslo_2)*sizeof(char), hash_2);     // Zamiana hasla liczby z przodu na MD5
      hash_1[16] = '\0';
      MD5_na_MD5hex(hash_1, MD5hex_1);                        // Zamiana MD5_1 na MD5hex_1
      hash_2[16] = '\0';
      MD5_na_MD5hex(hash_2, MD5hex_2);                        // Zamiana MD5_2 na MD5hex_2

      // Sprawdzenie hasel wygenerowanych i zamienionych na MD5
      for(int i=0;i<rozmiar;i++)
      {
        porownajHasla(MD5hex_1, haslo_1, i);                  // Porownanie hasla liczby z tylu
        porownajHasla(MD5hex_2, haslo_2, i);                  // Porownanie hasla liczby z przodu
      }

      int out=0;

      while(!out)
      {
        // Funkcja generujaca liczby z przodu i z tylu hasla
  	    out = dodajLiczby(haslo_1, haslo_2, dlugoscSlowa, iloscNumerow);

	      if(!out)
	      {
	        // MD5 DLA LICZB
          MD5(haslo_1, strlen(haslo_1)*sizeof(char), hash_1); // Zamiana hasla liczby z tylu na MD5
          MD5(haslo_2, strlen(haslo_2)*sizeof(char), hash_2); // Zamiana hasla liczby z przodu na MD5
          hash_1[16] = '\0';
          MD5_na_MD5hex(hash_1, MD5hex_1);                    // Zamiana MD5_1 na MD5hex_1
          hash_2[16] = '\0';
          MD5_na_MD5hex(hash_2, MD5hex_2);                    // Zamiana MD5_2 na MD5hex_2

          // Sprawdzenie hasel wygenerowanych i zamienionych na MD5
          for(int i=0;i<rozmiar;i++)
          {
            porownajHasla(MD5hex_1, haslo_1, i);
            porownajHasla(MD5hex_2, haslo_2, i);
          }
	      }
      }
    }
    iloscNumerow++;                // Dodanie kolejnego numeru z przodu/tylu hasla
  }

  // Uwalnianie pamieci
  pthread_mutex_lock(&mutex);    // Startujemy mutex
  free(haslo_1);
  free(haslo_2);
  pthread_mutex_unlock(&mutex);  // Konczymy mutex
}

















// Konsument: Wypisuje rozszyfrowane hasla na biezaco, oraz lapie sygnal SIGHUP
void *Konsument()
{
  while(1)
  {
    while(rozkodowaneHasla==NULL){}                   // Pusta petla - brak rozkodowanego hasla

    printf("Zlamane haslo: %s %s \n",rozkodowaneHaslaMD5, rozkodowaneHasla);

    pthread_mutex_lock(&mutex);                       // Startujemy mutex
    zakodowaneHasla[indeksZdekodowanegoHasla][0]='*'; // Oznaczenie zdekodowanego hasla
    free(rozkodowaneHaslaMD5);
    rozkodowaneHaslaMD5=NULL;
    free(rozkodowaneHasla);
    rozkodowaneHasla=NULL;
    iloscRozkodowanych++;
    pthread_mutex_unlock(&mutex);                     // Konczymy mutex

    signal(SIGHUP,sig_handler);                       // Wywolanie sig_handleraWylapywanie sygnalu
  }
}










int main(int argc, char* argv[])
{
  size_t dlugosc_slowa;                                       // Dlugosc pojedynczego slowa ze slownika
  char tmp[1024];                                             // Zmienna pomocnicza dla slownika
  char *slowo=NULL;                                           // Slowo zczytane z pliku ze slownikiem
  char **SLOWNIK;                                             // Zmienna do alokacji pamieci na slownik
  int ilosc_slow=0;                                           // Ilosc slow w slowniku
  struct Struktura_SLOWNIK Slownik_Argument;                  // Struktura, ktora bedzie przekazywana do producentow
  char q;                                                     // Wyjscie z programu
  pthread_t producent0, producent1, producent2, konsument;    // Watki
  void *status;                                               // Zmienna do join

  pid = getpid();                                             // Uzyskanie PID dla programu




  FILE *plikHasla = fopen(argv[1],"r");                       // Wczytanie pliku z zahaszowanymi haslami
  int i=0;
  while(fscanf(plikHasla, "%s",zakodowaneHasla[i])!=EOF)      // Wczytywaine do tablicy zahaszowanych hasel w petli, az do konca pliku wejsciowego
  {
    zakodowaneHasla[i][rozmiar_hasla]='\0';                   // Dodanie Null na końcu
    i++;
  }
  fclose(plikHasla);                                          // Zamkniecie pliku z zahaszowanymi haslami




  FILE *plikSlownik = fopen(argv[2],"r");                     // Wczytanie pliku ze slownikiem
  SLOWNIK = (char**)malloc(sizeof(char*));                    // Alokacja pamięci
  while(fscanf(plikSlownik,"%s",tmp)!=EOF)                    // Wczytywaine wyrazow slownika w petli, az do konca pliku wejsciowego
  {
    dlugosc_slowa = strlen(tmp);                              // Zapisanie dlugosci sczytanego słowa
    slowo = (char*)malloc(dlugosc_slowa+1);                   // Alokacja pamieci dla slowa
    for(int i=0;i<dlugosc_slowa;i++)                          // Petla zapisujaca slowo
    {
      slowo[i]=tmp[i];                                        // Podpisanie slowa z tmp do zmiennej slowo
    }
    slowo[dlugosc_slowa]='\0';                                // Dodanie Null na końcu
    ilosc_slow++;

    if(ilosc_slow > 1)
    {
      SLOWNIK = (char**)realloc(SLOWNIK,ilosc_slow*sizeof(char*));  // Alokacja pamieci dla slownika
    }
    SLOWNIK[ilosc_slow-1]=slowo;                                    // Dopisanie odczytanego slowa na koniec slownika
  }
  fclose(plikSlownik);                                              // Zamkniecie pliku ze slownikiem






  // Przepisanie slownika do struktury SLOWNIK
  Slownik_Argument.SLOWNIK=SLOWNIK;
  Slownik_Argument.dlugoscSLOWNIK=ilosc_slow;






  // Tworzenie watkow Producenta0, Producenta1, Producenta2 i Konsumenta
  int prod0 = pthread_create(&producent0,NULL,Producent_0,(void *)&Slownik_Argument);
  int prod1 = pthread_create(&producent1,NULL,Producent_1,(void *)&Slownik_Argument);
  int prod2 = pthread_create(&producent2,NULL,Producent_2,(void *)&Slownik_Argument);
  int konsu = pthread_create(&konsument,NULL,Konsument,NULL);






  while(1)
  {
    scanf("%c",&q);               // Scanf w nieskonczonej petli
    if (q =='q')                  // Zakonczenie programu gdy podamy q
    {
      printf("Koniec programu, sygnal SIGHUP \n");
      kill(pid,SIGHUP);           // Wyslanie sygnalu SIGHUP

      // Oczekiwanie na zakonczenie watkow
      pthread_join(producent0,&status);
      pthread_join(producent1,&status);
      pthread_join(producent2,&status);

      for(int i=0;i<ilosc_slow;i++)     // Uwalnianie pamięci slownika
      {
        free(SLOWNIK[i]);
      }
      free(SLOWNIK);
      pthread_exit(NULL);
    }
  }
}
