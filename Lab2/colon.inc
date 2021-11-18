%define next 0
%macro colon 2
    %2:	
	dq next 
    	db %1, 0
%define next %2
%endmacro
