\\ Find the largest factor pi^mi of a factorization n = sum(pi^mi)
largest_factor(factors) =
{ my(max_val = 0);
  foreach(Vec(mattranspose(factors)), x,
	if(x[1]^x[2] > max_val,
	   max_val = x[1]^x[2],
	  );
	);
  return (max_val);
}


\\ Find an elliptic curve with smooth cardinal
find_smooth_curve(prime, factor_limit) =
{ my(a, b, E, max_factor);
  max_factor = prime;
  while(max_factor > factor_limit,
    a = random(prime-1); b = random(prime-1);
	if (4*a^3 + 27*b^2 == 0, next(1),);
    E = ellinit([a, b]*Mod(1, prime));
	\\ factorization of Card(E), abord if it takes more than 10s
	factors = alarm(10, factor(ellcard(E)));
	if (type(factors) == "t_ERROR", next(1),);
	max_factor = largest_factor(factors);
	);
  return ([a, b]);
}


\\ Print curve parameters to file
curve_to_file(prime, ab, file) =
{ my(E, card, G);
  E = ellinit([ab[1], ab[2]]*Mod(1, prime));
  card = ellcard(E);
  G = ellgenerators(E);
  
  write(file, "p = ", prime);
  write(file, "a = ", ab[1]);
  write(file, "b = ", ab[2]);
  write(file, "card = ", card);
  write(file, "G = ", G);
}


\\ For each prime, find a smooth curves and print relevant info to file
get_curves(primes, factor_limit, file) =
{ my(ab);
  foreach(primes, p,
    print("searching weak curve over Fp with p = ", p);
	ab = find_smooth_curve(p, factor_limit);
	print("curve found ", ab);
	curve_to_file(p, ab, file);
	)
}



\\ script
default(parisize, 120000000); \\ set stack memory to 120Mb
primes_ = [\
0xcfbdb2e7e60f05d7389c4cbaed94e97f77c09c3ff5e3aacf,\
0xbf52c053869a8e6f51e8894365d09e4788b727ec5941734f,\
0xefe54b6268aba66e87b7e32d2038df43cac3886c3a84f18b5baa0a04817bbd27,\
2^255 - 19];
factor_limit_ = 2^40;
file_ = "D:/dev/root-me/_utils/smooth_curves.txt";

get_curves(primes_, factor_limit_, file_);