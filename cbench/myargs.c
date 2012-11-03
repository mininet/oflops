#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myargs.h"

static int
count_options(struct myargs options[]);
static int
find_arg(struct myargs options[], char * argname);

/************************************************************************/
void 
myargs_usage(struct myargs options[], char * title, char * s1, char * s2, int exit_val)
{
    #define AFMT "-20"
    #define OFMT "6"
    #define FMT "-40"
    struct myargs * optptr;
    if(s1)
        fprintf(stderr, "%s", s1);
    if(s2)
        fprintf(stderr, " %s", s2);
    if (s1 || s2)
        fprintf(stderr, "\n");
    if(title)
        fprintf(stderr, "%s\n", title);
    for( optptr = &options[0]; optptr->name != NULL ; optptr++)
    {
        fprintf(stderr, "   -%c/--%"AFMT"s  ", optptr->shortname, optptr->name);
        switch(optptr->type)
        {
            case MYARGS_NONE:
                fprintf(stderr, " %"OFMT"s %"FMT"s\n", "",optptr->comment);
                break;
            case MYARGS_INTEGER:
                fprintf(stderr, " %"OFMT"s %"FMT"s (%d)\n", "<int>", optptr->comment, optptr->default_val.integer);
                break;
            case MYARGS_FLAG:
                fprintf(stderr, " %"OFMT"s %"FMT"s (%s)\n", "", optptr->comment, optptr->default_val.flag? "on" : "off");
                break;
            case MYARGS_STRING:
                fprintf(stderr, " %"OFMT"s %"FMT"s (\"%s\")\n", "<str>", optptr->comment, optptr->default_val.string);
                break;
            case MYAGRS_DECIMAL:
                fprintf(stderr, " %"OFMT"s %"FMT"s (%lf)\n", "<real>", optptr->comment, optptr->default_val.decimal);
                break;
            default: 
                fprintf(stderr, "--- unhandled argument type %d", optptr->type);
                abort();
        };
    }
    fprintf(stderr, "\n");
    exit(exit_val);
}
/************************************************************************/
const struct option *
myargs_to_long(struct myargs options[])
{
    struct option * longopts;
    int n = count_options(options);
    int i;
    longopts = malloc(sizeof(struct option) * (n+1));
    for(i=0;i<=n;i++)
    {
        if(options[i].name)
            longopts[i].name = strdup(options[i].name);
        else 
            longopts[i].name = NULL;
        if( options[i].type == MYARGS_NONE ) 
            longopts[i].has_arg = no_argument;
        else if ( options[i].type == MYARGS_FLAG)
            longopts[i].has_arg = optional_argument;
        else
            longopts[i].has_arg = required_argument;
        longopts[i].flag =  NULL;
        longopts[i].val  = options[i].shortname;
    }
    return longopts;
}
/************************************************************************/
char * 
myargs_to_short(struct myargs options[])
{
    char * shortargs;
    int n = count_options(options);
    int i;
    int len=0;
    int max = n*2 + 1;
    shortargs = malloc(max);
    for(i=0; i< n; i++)
    {
        len+= snprintf(&shortargs[len], max-len, "%c", 
                options[i].shortname);
        if(options[i].type != MYARGS_NONE && options[i].type != MYARGS_FLAG)
            len+= snprintf(&shortargs[len], max-len, ":");
    }
    shortargs[len]=0;
    return shortargs;
}
/************************************************************************/
int 
count_options(struct myargs options[])
{
    int count = 0;
    struct myargs *opt;
    for ( opt = &options[0]; opt->name != NULL; opt++)
        count++;
    return count;
}
/************************************************************************/
int 
find_arg(struct myargs options[], char * arg)
{
    int i = 0;
    struct myargs *opt;
    for ( opt = &options[0]; opt->name != NULL; opt++)
    {
        if(!strcmp(opt->name, arg))
            return i;
        i++;
    }
    return -1;
}
/************************************************************************/
char * 
myargs_get_default_string(struct myargs options[], char * argname)
{
    int ARGNAME_NOTFOUND = -1;
    int i = find_arg(options,argname);
    assert(i != ARGNAME_NOTFOUND);
    assert(options[i].type == MYARGS_STRING);
    return options[i].default_val.string;
}
/************************************************************************/
int
myargs_get_default_integer(struct myargs options[], char * argname)
{
    int ARGNAME_NOTFOUND = -1;
    int i = find_arg(options,argname);
    assert(i != ARGNAME_NOTFOUND);
    assert(options[i].type == MYARGS_INTEGER);
    return options[i].default_val.integer;
}
/************************************************************************/
short
myargs_get_default_flag(struct myargs options[], char * argname)
{
    int ARGNAME_NOTFOUND = -1;
    int i = find_arg(options,argname);
    assert(i != ARGNAME_NOTFOUND);
    assert(options[i].type == MYARGS_FLAG);
    return options[i].default_val.flag;
}
