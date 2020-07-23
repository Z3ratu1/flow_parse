#ifndef  MYSQLCONNECTOR_H
#define  MYSQLCONNECTOR_H
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sstream>
#include <functional>
#include <unordered_map>
#include <postgresql/libpq-fe.h>
#include <postgresql/libpq/libpq-fs.h>
#include"base_type.h"
using namespace std;

void initDict(unordered_map<Tuble, int, hashTuble> &dict)	//初始化筛查字典 slice: 
{
	string strSql = "host = 127.0.0.1 port = 5432 dbname = capture user = capture password = cap1234";
	PGconn* conn;
	PGresult* res;
	conn = PQconnectdb(strSql.c_str());
	if (PQstatus(conn) != CONNECTION_OK) 
	{
		cerr << "cannot connect to database" << endl;
		PQfinish(conn);
		return;
	}
	else 
	{
		cout << "Connected" << endl;
	}
	const char* sql_query = "select ip, port from server_detection.http_list";
	res = PQexec(conn, sql_query);
	cout <<sql_query << endl;
	if (PQresultStatus(res) != PGRES_TUPLES_OK) 
	{
		cerr << "exec query failed" << endl;
		PQclear(res);
		return ;
	}
	uint32_t res_ip, i;
	uint16_t res_port;
	uint32_t res_num = PQntuples(res);

	for (i = 0; i < res_num; i++) 
	{
		res_ip = atoi(PQgetvalue(res, i, 0));
		res_port = atoi(PQgetvalue(res, i, 1));
		//取消端口过滤
		Tuble d(res_port, res_ip);
		pair<Tuble, int>ip_info(d, i);
		dict.insert(ip_info);
	}
	PQclear(res);
	// cout << "init Dict success" << endl;
}

#endif
