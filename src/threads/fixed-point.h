#ifndef FIXEDPOINT_H
#define FIXEDPOINT_H

/* This is a 17.14 fixed point implementation using a 32 bit 
signed int. 

	whole part max value is 17 Bits for whole = 2^18 - 1 = 262143
	fractional min = 1/(2^15 -1) = 0.000030519 
	shifting factor = 2^14 = 16384
	rounding factor = 2^13 = (shifting factor)/ 2 = 8192
*/
#define shift 16384

#define round 8192

//***************** CONVERSIONS ***************************

//INT 2 FLOAT
#define INT2FLOAT(x) ((x) > 262143) ? (x) : ((x)*shift)

//FLOAT 2 INT ROUNDED
#define FLOAT2INTR(x) (((x)>=0 ) ? (((x)+round)/shift) : (((x)-round)/shift))

//FLOAT 2 INT
#define FLOAT2INT(x) (x)/shift 


//**************** ADDITION & SUBTRACTION *****************

//FLOAT + FLOAT
#define ADDFF(x,y) ((x)+(y))

//FLOAT - FLOAT
#define SUBFF(x,y) ((x)-(y))

//FLOAT + INT
#define ADDFI(x,i) ((x)+(i)*shift)

//FLOAT - INT
#define SUBFI(x,i) ((x)-(i)*shift)

//*****************MULTIPLICATION ************************

//FLOAT x FLOAT
#define MULTFF(x,y) ((((int64_t)x)*(y))/shift)

//FLOAT x INT
#define MULTFI(x,i) ((x)*(i))

//******************** DIVISION ***************************

// FLOAT / FLOAT
#define DIVFF(x,y) (((int64_t)x)*(shift))/(y)

// FLOAT / INT
#define DIVFI(x,i) ((x)/(i))

#endif
