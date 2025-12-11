#include<stdio.h>
#include<string.h>
#include<stdlib.h>

char* userID;
int cookie = 45; //user specific. But now just set to '45' 
int global_value = 0;

char* gets(char* str)
{
    int c;
    char* s = str;
    while ((c = getchar()) != '\n' && c != EOF)
        *s++ = c;
    *s = '\0';
    return str;
}

void bang(int val)
{
  if (global_value == cookie)
      printf("Bang!: You set global_value to 0x%x\n",global_value);
  else
      printf("Bang!:  Attacked!!!!!!!!!!!!!!!!!!!\n"); 
  exit(0); 
}

void fizz(int val)
{
  if (val == cookie) 
       printf("Fizz!: You called fizz(0x%x)\n", val);
  else
       printf("Fizz!: Attacked!!!!!!!!!!!!!!!!\n"); 
   exit(0);
}

void smoke()
{
   printf("Smoke!: You called smoke()\n"); 
   exit(0);
}

//calculate a unique number for 'userID'. 
//目前都返回一个0x11223344
int uniqueval()
{
   int i;
   i = userID[0];
   return 0x11223344;
}

#define NORMAL_BUFFER_SIZE 32
// Get input data, fill in buffer */
int getbuf()
{
   int var_getbuf;
   char buf[NORMAL_BUFFER_SIZE];
   printf("Please type a string (< %d chars):",NORMAL_BUFFER_SIZE);
   gets(buf);
   return 1;
}

void test()
{
  int val;
  /* Put canary on stack to detect possible corruption */ 
  volatile int local = uniqueval();
 
  val = getbuf();

  /*Check for corrupted stack: local的值又没有被getbuf()函数破坏？*/ 
    if (local != uniqueval())
       printf("Sabotaged!: the stack has been corrupted\n"); 
    else if (val == cookie) 
	   printf("Boom!:  success\n"); 
    else 
	   printf("getbuf() returned 0x%x\n", val);
}
 
#define KABOOM_BUFFER_SIZE 512
//getbufn() uses a bigger buffer than getbuf() 
int getbufn()
{
    char buf[KABOOM_BUFFER_SIZE];
    printf("Please type a string (< %d chars):",KABOOM_BUFFER_SIZE);
    gets(buf);
    return 1;
}

void testn()
{
    int val;
    volatile int local = uniqueval();
    val = getbufn();
    /* Check for corrupted stack */
    if (local != uniqueval())
        printf("Sabotaged!: the stack has been corrupted\n");
    else if (val == cookie)
        printf("KABOOM!: success\n");
    else
        printf("getbufn returned 0x%x\n", val);
}

//run this program with 2 any params such as "userID n" to test 'Kaboom' attack.
int main(int argc, char**argv)
{
    int i;
    if (argc <2 )
    {
         printf("Usage: %s <userID> [n]\r\n",argv[0]);
         return 0;
    }
    userID = argv[1];

    if (argc >2 )
    {
        //experiment 'kaboom'
        printf("--- calling testn() for 'kaboom' test---\n"); //在windows系统下，回车换行符号是"\r\n".但是在Linux系统下是没有"\r"符号的。
        testn();
    }
    else
    {
        //experiments exept 'kaboom'
        printf("--- calling test()---\n");
        test();
    }
}
