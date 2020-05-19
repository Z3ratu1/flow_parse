#ifndef  MYSQLCONNECTOR_H
#define  MYSQLCONNECTOR_H
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <functional>
#include <unordered_map>
#include <postgresql/libpq-fe.h>
#include <postgresql/libpq/libpq-fs.h>
using namespace std;

void initDict(unordered_map<string, int> &dict)	//������
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
	const char* sql_query = "select ip, port from server_detection.server_index_list where last_detect_code = 2147483648;";
	res = PQexec(conn, sql_query);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) 
	{
		cerr << "exec query failed" << endl;
		PQclear(res);
		return ;
	}
	uint32_t res_ip, i;
	uint16_t res_port;
	uint32_t res_num = PQntuples(res);
	//��ɸ�ֵ��ʼ��?
	for (i = 0; i < res_num; i++) 
	{
		res_ip = atoi(PQgetvalue(res, i, 0));
		res_port = atoi(PQgetvalue(res, i, 1));
    //if(res_port == 80 || res_port == 443)
		//{
   		  //cout << res_ip << "," << res_port << endl;
        pair<string, int>ip_info(to_string(res_ip)+to_string(res_port), i);
		    dict.insert(ip_info);
    //}
	}
	PQclear(res);
	cout << "init Dict success" << endl;
}

#endif
