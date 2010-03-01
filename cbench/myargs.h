#ifndef MYARGS_H
#define MYARGS_H

#include <getopt.h>

enum myargs_type {
    MYARGS_NONE,
    MYARGS_INTEGER,
    MYARGS_FLAG,
    MYARGS_STRING,
    MYAGRS_DECIMAL
};

struct myargs {
    char *  name;
    char    shortname;
    char *  comment;
    enum myargs_type type;
    union myarg_value
    {
        short   none;
        int     integer;
        short   flag;
        char *  string;
        double  decimal;
    } default_val;
};



/** 
 *  print
 *      "$s1 : $s2\n"
 *      "$title\n"
 *      "opt1 ..."
 *      "opt2 ..."
 *
 *      "\n"
 *      and then call exit(exit_val)
 *
 *      @param options A list of myargs where the last arg is all zeros
 *      @param title    A string to print in the usage, i.e., "program name [options]"
 *      @param  s1      An optional string to print: if NULL, nothing is printed
 *      @param  s2      An optional string to print: if NULL, nothing is printed
 *      @param  exit_val    The value to pass to exit()
 */


void 
myargs_usage(struct myargs options[], char * title, char * s1, char * s2, int exit_val);


/**
 * Return a list of struct options suitable for getopt_long()
 * @param options   A list of myargs where the last arg is all zeros
 * @return A list of long options
 */

const struct option * 
myargs_to_long(struct myargs options[]);

/**
 * Return a string of options suitable for getopt()
 * @param options   A list of myargs where the last arg is all zeros
 * @return A string with colons for all of the short names of the options, i.e., "e:fg:"
 */
char *
myargs_to_short(struct myargs options[]);


/** 
 * Return the default value for the option
 *  abort() if does not exist or is not a string
 *  @param options   A list of myargs where the last arg is all zeros
 *  @param argname   The long name of an argument
 *  @return A string
 */
char * 
myargs_get_default_string(struct myargs options[], char * argname);
/** 
 * Return the default value for the option
 *  abort() if does not exist or is not an int
 *  @param options   A list of myargs where the last arg is all zeros
 *  @param argname   The long name of an argument
 *  @return An int
 */
int 
myargs_get_default_integer(struct myargs options[], char * argname);
/** 
 * Return the default value for the option
 *  abort() if does not exist or is not a flag
 *  @param options   A list of myargs where the last arg is all zeros
 *  @param argname   The long name of an argument
 *  @return A zero for off, a one for on
 */
short 
myargs_get_default_flag(struct myargs options[], char * argname);
/** 
 * Return the default value for the option
 *  abort() if does not exist or is not a decimal
 *  @param options   A list of myargs where the last arg is all zeros
 *  @param argname   The long name of an argument
 *  @return A double
 */
double 
myargs_get_default_decimal(struct myargs options[], char * argname);


#endif
