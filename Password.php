<?php

namespace Api\Account\Password;

use Api\Core\SQLQueries as ApiCoreSQLQueries;

class Password
{
    const USER_DB           = "rws";
    const USER_TABLE        = "user";
    const USER_TABLE_ID     = "id";

    const PASS_COST         = "10";
    const CHARS_SET         = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./";

    private static $sqlh    = null;

    public static function verifyUserPassword ($username, $password) {
        $user_id    = 0;
        $sqlh       = self::connect();
        $query      = $sqlh->getSelectSQL(false, ["id","SUBSTRING(password_hash,11,53) as real_hash"], ["username"=>$username]);
        $rows       = $sqlh->getSelectResults($query);
        
        if (count($rows)) {
            foreach ($rows as $num => $arr) {
                if ($arr["real_hash"] && password_verify($password, self::getCostPrefix() . $arr["real_hash"])) 
                    return $arr["id"];
            }
        }

        return $user_id;
    }

    public static function updateUserPasswordHash ($password, $user_id, $print = false) {
        $sqlh           = self::connect();
        $password_hash  = self::buildPasswordHash($password);
        $arr_pass       = ["password_hash" => $password_hash];
        $query          = $sqlh->getUpdateSQL($arr_pass, true, $user_id);
        $sqlh->execSQL($query);

        if ($print)
            echo $password . ": " . $password_hash . "\n";
    }

    private static function buildPasswordHash($password) {

        return self::getMasqueSalt() . substr(self::getRealPasswordHash($password), 7) . self::getMasqueSalt(9);
    }

    private static function getRealPasswordHash($password) {

        return password_hash($password, PASSWORD_BCRYPT, ["cost" => self::PASS_COST]);
    }

    private static function getMasqueSalt ($length = 10 ) {

        return substr(str_shuffle(self::CHARS_SET), 0, $length);
    }

    private static function getCostPrefix() {
        
        return "\$2y\$" . self::PASS_COST  . "\$";
    }

    private static function connect()
    {
        if (!self::$sqlh) {
            self::$sqlh = new ApiCoreSQLQueries\SQLQueries(self::USER_DB,self::USER_TABLE,self::USER_TABLE_ID);
        }

        return self::$sqlh;
    }

}