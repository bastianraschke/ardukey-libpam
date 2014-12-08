CREATE TABLE API
  ( id NUMBER (11) NOT NULL , 
    secret NUMBER (64) NOT NULL,
    PRIMARY KEY ( id )
  ) ;

CREATE TABLE OTP
  (
    publicid       VARCHAR2 (12) NOT NULL ,
    secretid       VARCHAR2 (12) NOT NULL ,
    sessioncounter NUMBER (3) NOT NULL ,
    counter        NUMBER (5) NOT NULL ,
    timestamp      NUMBER (8) ,
    aeskey         VARCHAR2 (32) NOT NULL ,
    created        DATE ,
    status         NUMBER (1) NOT NULL ,
    PRIMARY KEY ( publicid )
  ) ;
