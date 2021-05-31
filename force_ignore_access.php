<?php
class IgnoreAccess
{
        public $hosts_list = array();
        public $ua_list    = array();
        public $ref_list   = array();
        private function set_403()
        {
                header("HTTP",true,403);
                exit(1);
        }
        private function check_array($array=array())
        {
                if (is_array($array)!==FALSE && count($array)>0)
                {
                        return TRUE;
                }
                else
                {
                        return FALSE;
                }
        }
        private function is_host($addr="")
        {
                if ($addr == gethostbyaddr($addr))
                {
                        return FALSE;
                }
                else
                {
                        return TRUE;
                }
        }
        public function ignore($param=array(),$not_ipv4=FALSE)
        {
                $local_addr = array("127.0.","192.168.","::1");
                foreach($local_addr as $val)
                {
                        if (substr_count($param["addr"],$val)>0)
                        {
                                return FALSE;
                        }
                }
                if ($not_ipv4!==FALSE && $this->is_host($param["addr"])===FALSE)
                {
                        $this->set_403();
                }
                if ($this->check_array($this->ua_list)!==FALSE)
                {
                        foreach ($this->ua_list as $val)
                        {
                                if (substr_count($param["ua"],$val)>0)
                                {
                                        $this->set_403();
                                }
                        }
                }
                if ($this->check_array($this->hosts_list)!==FALSE)
                {
                        foreach ($this->hosts_list as $val)
                        {
                                if (substr_count(gethostbyaddr($param["addr"]),$val)>0)
                                {
                                        $this->set_403();
                                }
                        }
                }
                if ($this->check_array($this->ref_list)!==FALSE && strlen($param["ref"])>0)
                {
                        foreach ($this->ref_list as $val)
                        {
                                if (substr_count($param["ref"],$val)>0)
                                {
                                        $this->set_403();
                                }
                        }
                }
        }
}
$my_ignore_access = new IgnoreAccess;
 
$my_ignore_access->hosts_list = array(
        "ignore_host_a.net",
        "ignore_host_b.net",
        "ignore_host_c.net"
);
 
$my_ignore_access->ua_list = array(
        "ignore_ua_a",
        "ignore_ua_b",
        "ignore_ua_c"
);
 
$my_ignore_access->ref_list = array(
        "ignore_referer_a.net",
        "ignore_referer_b.net",
        "ignore_referer_c.net"
);
 
$ignore_point["ip"]      = (isset($_SERVER["REMOTE_ADDR"]))     ? $_SERVER["REMOTE_ADDR"]      : NULL;
$ignore_point["ua"]      = (isset($_SERVER["HTTP_USER_AGENT"])) ? $_SERVER["HTTP_USER_AGENT"]  : NULL;
$ignore_point["referer"] = (isset($_SERVER["HTTP_REFERER"]))    ? $_SERVER["HTTP_REFERER"]     : NULL;
$my_ignore_access->ignore($ignore_point,FALSE);
