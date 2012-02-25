#include <stdio.h>
#include "scrollback.h"

int main()
{
    int i;
   scrollback_init(10, 80);
   for(i=0; i<10; i++)
    {
        char buf[80];
        snprintf(buf, 80, "Test %d", i);
        scrollback_putline(buf);
    }
  char ** mylines = scrollback_getall();
  char **currline = mylines;
  while(*currline != NULL)
  {
    printf("Found line: %s\n", *currline);
    currline++;
  }
  for(i=20; i<25; i++)
  {
     char buf[80];
     snprintf(buf, 80, "Test %d", i);
     scrollback_putline(buf);
  }
   currline = mylines;
   while(*currline != NULL)
   {
     printf("2Found line: %s\n", *currline);
     currline++;
   }
}