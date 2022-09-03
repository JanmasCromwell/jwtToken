<?php
#+------------------------------------------------------------------
#| 普通的。
#+------------------------------------------------------------------
#| Author:Janmas Cromwell <janmas-cromwell@outlook.com>
#+------------------------------------------------------------------

include '../vendor/autoload.php';

$key = 'MIICXQIBAAKBgQDdzEzzb6Eta3ICjMTyxMDxb1J9eRtOQIJfQQb4r7Zvg7SaGgryMJVrgNozPfs2hnHyj7MitpLZzIDIlTXrwo7eSTWOvYwLEg9JegDpHk4JU4oijQepgDnLZW6JLos2eyW4AY5vpmK8PU57Zh6C2EraEfN284iFhrny1dDIh8tI1QIDAQABAoGAQl3RYL40Qjz2PmEUxXeuLBAdZMIKM54F5K62gU9CjZehQMMuJ032R9akc9TGCIiuK+Bnv6lVw6n3lw1etw7eZIJbh5l/RVykpaVPozq74hgIOIN4I80+cSwPOiHQDwrbqZ78Iw7Y4JXIJNc98d+qcVl7foxf+p7hID9SkxGxj8ECQQD3ZjsKQ415BZJ0bPz4xZZLPqQaXf8jtOim2+ms3m9E4+wE0HYw2U2ZpoAek/uumylmkaQEnlaNDqb18NwBtxsJAkEA5YI6LaUxYuniVl5q9CwXLn0KvH2nriIOp0c3qC7ydnns2aeSf3w6dvKlQgWXgyHMw4xUR5MSCP+dOYXQ8vIWbQJAAKNR2afs8Hf0NbqmOFoCFjWWJL9DTitEQlHk215DeTEBRc3n0B5vVcsZH3sQNhYOWEZd3uktnfWAtrelSZfYSQJBAN5P6P7x9wazOxUiXEOsub/ES7QNm3EneD481ALLhv2QWQb0NQncUd2KaN2tAPh6sxfwRGsYYO3qfGeN4bqTGXkCQQDShb0JuGBOkeyKXOpxhdg2+q+yN1IoQbtJE9/xw/ukR2170dwmaesRMMqGOr7bv507NU8ZM9h2yzCL4paqYPWb';


$builder = (new \Janmas\Jwt\JWT())->builder($key);
$signer = new \Janmas\Jwt\Signer\SHA256();
$jwt = $builder->audience('asd')
    ->id(uniqid())
    ->expiration(time() + 6000)
    ->issuer('JWT_ADMIN')
    ->audience('http://www.example.com')
    ->notBefore(time()+60)
    ->issuedAt(time())
    ->subject('aaaaaaa')
    ->claims(['asd' => 123123123, 'asqwe' => 'asdasdasdasdasds'])
    ->withClaims('name', 'JanmasCromwell')
    ->sign($signer);

$all = (new \Janmas\Jwt\JWT())->verify($jwt, $key);
var_dump($all);
