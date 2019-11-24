export async function getJSON(url) {
  const response = await fetch(url);
  return await response.json();
}
