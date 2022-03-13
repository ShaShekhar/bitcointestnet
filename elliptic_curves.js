// % is remainder operator not modulo.
function calc_mod(x, p){
	let mod;
	if(x < 0n){
		if((x+p) < 0n){
			mod = ((-1n*x/p)+1n)*p + x;
		} else {
			mod =  x + p;
		}
	} else{
		mod =  x % p;
	}
	return mod;
}

// To calculate the inverse
// EDGE CASE: what if one no. is +ve and other -ve.
function extended_euclidean_algorithm(a, b){
	// return gcd(r0, r1) such that s*r0 + t*r1 == gcd(r0, r1)
	// a > b or (r0 > r1)
	let old_r = a, r = b;
	let old_s = 1n, s = 0n;
	let old_t = 0n, t = 1n;

	let new_r, new_s, new_t, quotient;

	while (r !== 0n){
		if(old_r < 0n && r < 0n){
			quotient = old_r / r;
		} else if (old_r < 0n || r < 0n){
			// BigInt division round off for -ve no., so subtract 1n
			quotient = (old_r / r) - 1n;
		} else {
			quotient = old_r / r;
		}

		new_r = old_r - quotient*r;
		old_r = r;
		r = new_r;

		new_s = old_s - quotient*s;
		old_s = s;
		s = new_s;

		new_t = old_t - quotient*t;
		old_t = t;
		t = new_t;
	}
	// console.log(`old_r: ${old_r}`);
	// console.log(`old_s: ${old_s}`);
	// console.log(`old_t: ${old_t}`);

	return [old_r, old_s, old_t];
}

function inverse(n, p){
	// return modular multiplicative inverse s.t (n * m) % p == 1
	const [gcd, x, y] = extended_euclidean_algorithm(n, p);
	const mod_x = calc_mod(x, p);
	// console.log(`mod: ${mod}`);
	return mod_x;
}


class Point {
	constructor(x, y){
		this.curve_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
		this.curve_a = 0x0000000000000000000000000000000000000000000000000000000000000000n;
		this.curve_b = 0x0000000000000000000000000000000000000000000000000000000000000007n;
		this.x = x;
		this.y = y;
	}

	add(other) {

		if (this == INF){
			// console.log('first point is INF!')
			return other;
		}
		if (other == INF){
			return this;
		}

		// handle special case of P + (-P) = 0
		if (this.x == other.x && this.y != other.y){
			return INF;
		}
		// compute the "slope"
		let m;
		if (this.x == other.x){ // this.y == other.y is guaranteed too per above check
			// console.log('added same point.');
			m = (3n * this.x**2n + this.curve_a) * inverse(2n * this.y, this.curve_p);
			m = calc_mod(m, this.curve_p);
		} else {
			// console.log('added different point')
			m = (this.y - other.y) * inverse(this.x - other.x, this.curve_p);
			m = calc_mod(m, this.curve_p);
			// console.log(`m: ${m}`);
		}

		// compute the new point
		let rx, ry;
		rx = (m**2n - this.x - other.x);
		rx = calc_mod(rx, this.curve_p);

		ry = ((m*(this.x - rx)) - this.y);
		// console.log(`ry: ${ry}`);
		ry = calc_mod(ry, this.curve_p);
		// console.log(`ry after mod: ${ry}`);

		return new Point(rx, ry);
	}

	multiply(k) {
		let result = INF;
		let append = this;

		while (k) {
			// console.log(k & 1n);
			if (k & 1n){
				result = result.add(append);
			}
			append = append.add(append);
			k = k >> 1n;
		}
		return result;
	}
}

// secp256k1 uses a = 0, b = 7, so we're dealing with the curve y^2 = x^3 + 7 (mod p)
const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
// the order of G is known and can be mathematically derived
const ORD_G = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

INF = new Point(null, null);

const G = new Point(Gx, Gy);

// for(let i = 1n; i < 20n; i++){
// 	const pk = G.multiply(i);
// 	console.log(`public key: ${pk.x}, ${pk.y}`);
// 	console.log('############################################');
// }

// we can verify that the generator point is indeed on the curve, i.e, y^2 = x^3 + 7
// let on_curve = ((G.y**2n - G.x**3n - G.curve_b) % G.curve_p) === 0n;
// console.log(`Generator is on the curve: ${on_curve}`);

// let random_x = 84747631942840761409198475171043116002924132430274400095798688737582350222083n;
// let random_y = 41667246332565885209668308841167516170410697202289401632214205549524252523359n;
// on_curve = ((random_y**2n - random_x**3n - G.curve_b) % G.curve_p) === 0n;
// on_curve = ((Math.pow(random_y, 2) - Math.pow(random_x, 3) - 7) % G.curve_p) === 0;
// console.log(`Random point is on the curve: ${on_curve}`);


// if our secret key was the integer 1, then our public key would just be G:
// let sk = 1
// const pk = G;
// console.log(`secret key: ${sk}`);
// console.log(`public key: ${pk.x}, ${pk.y}`);
// on_curve = ((pk.y**2n - pk.x**3n - pk.curve_b) % pk.curve_p) === 0n;
// on_curve = ((Math.pow(pk.y, 2) - Math.pow(pk.x, 3) - 7) % pk.curve_p) === 0;
// console.log(`Public key is on the curve: ${on_curve}`);

// if it was 2, the public key is G + G
// sk = 2;
// const pk1 = G.add(G);
// console.log(`secret key: ${sk}`);
// console.log(`public key: ${pk1.x}, ${pk1.y}`);
// on_curve = ((pk1.y**2n - pk1.x**3n - pk1.curve_b) % pk1.curve_p) === 0n;
// on_curve = ((Math.pow(pk1.y, 2) - Math.pow(pk1.x, 3) - 7) % pk1.curve_p) === 0;
// console.log(`Public key is on the curve: ${on_curve}`);

// // etc...
// sk = 3;
// const pk2 = G.add(G).add(G);
// console.log(`secret key: ${sk}`);
// console.log(`public key: ${pk2.x}, ${pk2.y}`);
// on_curve = ((pk2.y**2n - pk2.x**3n - pk2.curve_b) % pk2.curve_p) === 0n;
// on_curve = ((Math.pow(pk2.y, 2) - Math.pow(pk2.x, 3) - 7) % pk2.curve_p) === 0;
// console.log(`Public key is on the curve: ${on_curve}`);

// verify correctness
// console.log(G === G.multiply(1));
// a = G.add(G)
// b = G.multiply(2);

// console.log(a.x === b.x && a.y === b.y);
// console.log(G.add(G).add(G) === G.multiply(3));