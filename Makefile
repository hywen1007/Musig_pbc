all:
	gcc -o sig sig.c -g -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib -l pbc -l gmp