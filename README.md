# sha-256-arduino
Sha-256 Libruary for Arduino aplications. Has Very compact code 2240 bytes after compile.

# usage
```c
#include <SoftwareSerial.h>
#include "sha256.h"

void setup() {
  // for print control sample in console
  Serial.begin(9600);
}

void showHash(uint8_t * hash)
{
  for(int i = 0; i<DIGEST_LENGTH; i+=2)
  {
    byte b0 = *hash;
    hash++;
    byte *b1 = *hash;
    hash++;
    Serial.print(((unsigned long)b0)&255, HEX);
    Serial.print(((unsigned long)b1)&255, HEX);

  }
}

void loop() {
  uint8_t *message = "1";

  Digest sha256;
  sha256.update((const uint8_t *)message, 1);
  uint32_t * hash = sha256.digest();//return DIGEST_LENGTH bytes
  
 showHash((uint8_t *)hash);// -> "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"
}

// 3 550 bytes compiled for Arduino Nano/ATmega328P
```
