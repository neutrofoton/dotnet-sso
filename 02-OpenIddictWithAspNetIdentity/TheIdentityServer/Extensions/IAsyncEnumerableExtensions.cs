namespace TheIdentityServer.Extensions
{
    public static class IAsyncEnumerableExtensions
    {
        public static Task<List<T>> ToListAsync<T>(this IAsyncEnumerable<T> source)
        {
            if(source == null) 
                throw new ArgumentNullException(nameof(source));

            return ExecuteAsync();

            async Task<List<T>> ExecuteAsync()
            {
                var list = new List<T>();
                await foreach (var item in source)
                {
                    list.Add(item);
                }
                return list;
            }
        }
    }
}
