#!/bin/env ruby

require 'digest'

# Curve (secp256k1): y^2==x^3+7
$p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
$n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
$G = {
  x: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
  y: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
}

def verify_point(x, y)
  (y ** 2) % $p == (x ** 3 + 7) % $p
end

def mul(base, n, mod)
  result = 0
  (0...n).each { |_|
    result = (result + base) % mod
  }
  result
end

puts verify_point($G[:x], $G[:y])
for i in 1..13
  puts "8 * #{i} = #{mul(8, i, 47)}"
end

def mmi_naive(num, mod, target = 1)
  result = 0
  (1...).each do |multiplier|
    result = (result + num) % mod
    if result == target
      return multiplier
    end
  end
  fail
end

puts
puts mmi_naive(10, 47, 8)
puts mul(10, 29, 47)
puts mmi_naive(12, 47)

puts

def gcd(a, b)
  while true
    rem = a % b
    a = b
    b = rem
    return a if rem == 0
  end
end

def gcd_recursive(a, b)
  return a if b == 0
  gcd_recursive(b, a % b)
end

# puts gcd(18, 48)
# puts gcd(48, 18)
# puts gcd_recursive($G[:x], $G[:y])
# puts gcd_recursive($G[:y], $G[:x])
# puts gcd($G[:x], $G[:y])
# puts gcd($G[:y], $G[:x])

# gcd(18, 48)
# =gcd(18,12)
# =gcd(12,12)

puts mmi_naive(2, 7) #=>4

# max=91,pub=5,priv=29

def ff_mul(a, b, mod)
  (a * b) % mod
end

# requires mod to be prime
def ff_flt_div(a, b, mod)
  ff_mul(a, flt_modular_inverse(b, mod), mod)
end

def ff_exp(base, exp, mod)
  res = 1
  (0...exp).each do |_|
    t = res * base
    res = t % mod
  end
  res
end

puts ff_exp(12, 5, 91) #=>38
puts ff_exp(38, 29, 91) #=>12

def lcm(a, b)
  a * b / gcd(a, b)
end

puts lcm(4, 6) #=>12

def is_prime(n)
  (2...n).each { |i|
    return false if n % i == 0
  }
  true
end

def rsa_keys(p, q)
  fail unless is_prime p and is_prime q
  n = p * q
  ctf = lcm(p - 1, q - 1)
  # find an e (2<e<ctf) such that e and ctf are coprime
  e = 0
  (3...ctf).each do |i|
    if gcd(i, ctf) == 1
      e = i
      break
    end
  end
  fail if e == 0

  d = mmi_naive(e, ctf)
  {
    :mod => n,
    :pub => e,
    :priv => d,
  }
end

p = 61
q = 53
rsa = rsa_keys(p, q)
puts rsa
message = 1234
cipher = ff_exp(message, rsa[:pub], rsa[:mod])
puts ff_exp(cipher, rsa[:priv], rsa[:mod]) #=>1234

puts '--'

def bits(n)
  bits = []
  i = n
  while true
    rem = i % 2
    bits.push rem
    i = i / 2
    break if i == 0
  end
  bits.reverse!
  bits
end

def fast_ff_exp(base, exp, mod)
  bits = bits(exp)
  r = 1
  bits.each do |b|
    r = ff_exp(r, 2, mod)
    if b == 1
      r = ff_mul(r, base, mod)
    end
  end
  r
end

# Get the modular multiplicative inverse by Fermat's Little Theorem
# Requires: mod is prime
def flt_modular_inverse(n, mod)
  fast_ff_exp(n, mod - 2, mod)
end

puts fast_ff_exp(3, 14, 7)
puts fast_ff_exp(213, 2133241234314243121433412, 1628261) #=>1329663

puts flt_modular_inverse(5, 17) #=>7
puts flt_modular_inverse(34112321, 554628293147) #=>76240397852
puts flt_modular_inverse($G[:x], $p).to_s(16) #=>237afdf1d2938d86870aaeb8ad77626a67b8e794abfb076be61d003687ca9ef6

def ec_double(x, y, m = $p)
  s = ff_flt_div(3 * x ** 2, 2 * y, m)
  xx = (s ** 2 - 2 * x) % m
  yy = (s * (x - xx) - y) % m
  { :x => xx, :y => yy }
end

def ec_add(x1, y1, x2, y2, m = $p)
  s = ff_flt_div(y1 - y2, x1 - x2, m)
  xx = (s ** 2 - x1 - x2) % m
  yy = (s * (x1 - xx) - y1) % m
  { :x => xx, :y => yy }
end

puts '--'
puts ec_double(
       9897240716311993748443371784363277454480463369194559198340637884670963742771,
       2074964713434610613611913340035552794776406827166903390023967251694352397205
     )
p1 = {
  :x => 83385460941864588404643178647941993721755528492190818068949555598162037731803,
  :y => 68477374783790977615111220877294414962872299061240452048638213960953736655329
}
p2 = {
  :x => 65956364961380637843469509718029352582543542402436117989404566274623669301442,
  :y => 82691413128864751824463131354405310297502523194698064207942966391606705382392
}
p3 = {
  :x => 80553632333233300464758074306614490346905116920311067406818635320330519533753,
  :y => 72335125866925893800273156734035374768918655566838843506236277022697679552376
}
puts ec_add(p1[:x], p1[:y], p2[:x], p2[:y]) #=>p3

def ec_mul(x, y, n, m = $p)
  bits = bits(n)
  p = { :x => x, :y => y }
  # skip MSB
  bits.drop(1).each do |b|
    p = ec_double(p[:x], p[:y], m)
    if b == 1
      p = ec_add(p[:x], p[:y], x, y, m)
    end
  end
  p
end

def ec_mul_gp(k)
  ec_mul($G[:x], $G[:y], k)
end

#=>{:x=>101031181364592539890876441789639154400620913779307508770387032862319499840426, :y=>93211621457113221902577311243702142461359478895035279621948646517973885498790}
puts ec_mul($G[:x], $G[:y], 12324234213123)
puts ec_mul($G[:x], $G[:y], $p)[:x].to_s(16) #=>b42b34a9748238715c0b8b853b6939aabc3b5224bcdd4b4b65e902417e7af914
# puts ec_add($G[:x], $G[:y], $G[:x], -$G[:y])[:x].to_s(16)
puts '--'

prk = 0xc8bced509e98aa82dbfa2f628f69ffb59a5bc619ee8227bcffdcd5e50af2c83a
pk = ec_mul_gp(prk)
puts pk

def decompress_x_only_pub(x, m = $p)
  # solve y in the equation y^2==x^3+7
  y_sq = (x ** 3 + 7) % m
  # Secp256k1 is chosen in a special way so that the square root of y is y^((p+1)/4)
  y = fast_ff_exp(y_sq, ($p + 1) / 4, m)
  { :x => x, :y => y }
end

x = 0xb4632d08485ff1df2db55b9dafd23347d1c47a457072a1e87be26896549a8737
puts decompress_x_only_pub(x)[:y].to_s(16) #=>8ec38ff91d43e8c2092ebda601780485263da089465619e0358a5c1be7ac91f4

def ecdsa_sign(message, priv, k)
  fail if k >= $n
  z = Digest::SHA256::hexdigest(message).to_i(16)
  d = priv
  point_r = ec_mul_gp(k)
  r = point_r[:x]
  s = ff_flt_div(z + d * r, k, $n)
  { :r => r, :s => s }
end

puts '--'
k = 12345
z = 103318048148376957923607078689899464500752411597387986125144636642406244063093
d = 112757557418114203588093402336452206775565751179231977388358956335153294300646
r = 108607064596551879580190606910245687803607295064141551927605737287325610911759
s = ((z + r * d) * flt_modular_inverse(k, $n)) % $n
puts s.to_s

# SHA256 of 'hello': 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
k = 0x9301e848dff20e47ddc6bdbbbfb0ff781ac5264c16f4558f28eb3dcb2be346de
puts k.to_s(16)
prk = 0x5ca801c4d3d173de77aa8e70707b933ad4559a5c898e643df414ec9181de79a3
#=>{:r=>89224211084095434485181696734138068440296940549936199202503133855617683849638, :s=>19309331474632759252605438126475658209578916922748588370762191677349135823980}
signature = ecdsa_sign('hello', prk, k)
puts signature

puts '--'

def ecdsa_verify(msg, sig, pub)
  s = sig[:s]
  r = sig[:r]
  z = Digest::SHA256::hexdigest(msg).to_i(16)
  inverse = flt_modular_inverse(s, $n)
  point1 = ec_mul_gp(inverse * z)
  point2 = ec_mul(pub[:x], pub[:y], inverse * r)
  point3 = ec_add(point1[:x], point1[:y], point2[:x], point2[:y], $p)
  point3[:x] == r
end

pk = ec_mul_gp(prk)
puts ecdsa_verify('hello', signature, pk) #=>true

# 有限域、扩展欧几里德算法、费马小定理、贝祖定理、椭圆曲线乘法、快速幂（平方求幂）、快速椭圆乘（double-and-add）、……
