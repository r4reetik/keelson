// Ports that security-group checks treat as databases, shared by the cloud
// providers (AWS, Alibaba Cloud) so a port judged on one is judged on the other.

export const DATABASE_PORTS: Record<number, string> = {
  1433: "SQL Server",
  1521: "Oracle",
  3306: "MySQL",
  5432: "PostgreSQL",
  5439: "Redshift",
  6379: "Redis",
  9200: "Elasticsearch",
  11211: "Memcached",
  27017: "MongoDB",
};
