const { execSync } = require('child_process');
const fs = require('fs');

function getNewlyPublishedPosts() {
  try {
    // Get all posts that are now published (not future, not draft)
    const allPostsOutput = execSync('hugo list all', { encoding: 'utf-8' });
    const allPosts = parseHugoCSV(allPostsOutput);
    
    // Get posts that are still in the future
    let futurePosts = [];
    try {
      const futurePostsOutput = execSync('hugo list future', { encoding: 'utf-8' });
      futurePosts = parseHugoCSV(futurePostsOutput);
    } catch (e) {
      // No future posts or command failed - that's okay
      console.log('No future posts found or command failed:', e.message);
    }
    
    // Filter for posts published today
    const today = new Date();
    const todayString = today.toISOString().split('T')[0]; // YYYY-MM-DD format
    
    const publishedToday = allPosts.filter(post => {
      if (post.draft === 'true') return false;
      
      // Check if post's publish date is today
      const postDate = new Date(post.publishDate || post.date);
      const postDateString = postDate.toISOString().split('T')[0];
      
      return postDateString === todayString;
    });
    
    // Filter out posts that are still in the future
    const futurePostPaths = new Set(futurePosts.map(p => p.path));
    const newlyPublished = publishedToday.filter(post => !futurePostPaths.has(post.path));
    
    return { newlyPublished, publishedToday, futurePosts };
  } catch (error) {
    console.error('Error checking for newly published posts:', error);
    return { newlyPublished: [], publishedToday: [], futurePosts: [] };
  }
}

function parseHugoCSV(csvOutput) {
  const lines = csvOutput.trim().split('\n');
  if (lines.length < 2) return []; // No data rows
  
  const headers = lines[0].split(',');
  const posts = [];
  
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    
    // Parse CSV line (handling quoted fields)
    const values = parseCSVLine(line);
    const post = {};
    
    headers.forEach((header, index) => {
      post[header] = values[index] || '';
    });
    
    posts.push(post);
  }
  
  return posts;
}

function parseCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    
    if (char === '"' && (i === 0 || line[i-1] === ',')) {
      inQuotes = true;
    } else if (char === '"' && inQuotes && (i === line.length - 1 || line[i+1] === ',')) {
      inQuotes = false;
    } else if (char === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  
  result.push(current);
  return result;
}

function formatPostSummary(result) {
  const { newlyPublished, publishedToday, futurePosts } = result;
  
  let summary = '';
  
  // Report newly published posts
  if (newlyPublished.length === 0) {
    summary += 'No new posts published today.\n\n';
  } else {
    summary += `🎉 ${newlyPublished.length} new post${newlyPublished.length > 1 ? 's' : ''} published today:\n\n`;
    
    newlyPublished.forEach(post => {
      const postDate = new Date(post.publishDate || post.date);
      summary += `📝 **${post.title}**\n`;
      summary += `   📅 Published: ${postDate.toLocaleDateString()}\n`;
      summary += `   🔗 Path: ${post.path}\n`;
      if (post.permalink) {
        summary += `   🌐 URL: ${post.permalink}\n`;
      }
      summary += '\n';
    });
  }
  
  // Report upcoming posts
  if (futurePosts.length > 0) {
    // Sort future posts by publish date
    const sortedFuturePosts = futurePosts
      .map(post => ({
        ...post,
        publishDateTime: new Date(post.publishDate || post.date)
      }))
      .sort((a, b) => a.publishDateTime.getTime() - b.publishDateTime.getTime());
    
    summary += `📅 **Upcoming Posts (${futurePosts.length} scheduled):**\n\n`;
    
    // Show next 10 upcoming posts
    const postsToShow = sortedFuturePosts.slice(0, 10);
    postsToShow.forEach(post => {
      const postDate = post.publishDateTime;
      const daysFromNow = Math.ceil((postDate.getTime() - new Date().getTime()) / (1000 * 60 * 60 * 24));
      summary += `📄 **${post.title}**\n`;
      summary += `   📅 Scheduled: ${postDate.toLocaleDateString()} (in ${daysFromNow} day${daysFromNow > 1 ? 's' : ''}):\n`;
      summary += `   🔗 Path: ${post.path}\n`;
      summary += '\n';
    });
    
    if (futurePosts.length > 10) {
      summary += `   ... and ${futurePosts.length - 10} more upcoming posts\n\n`;
    }
  } else {
    summary += '📅 **No upcoming posts scheduled.**\n\n';
  }
  
  return summary;
}

// Test the script
console.log('Testing Hugo post detection script...\n');

const result = getNewlyPublishedPosts();
const summary = formatPostSummary(result);

console.log(summary);

console.log('\nDetailed results:');
console.log('All posts count:', result.newlyPublished.length + result.futurePosts.length);
console.log('Newly published:', result.newlyPublished.length);
console.log('Future posts:', result.futurePosts.length);

if (result.newlyPublished.length > 0) {
  console.log('\nNewly published posts:');
  result.newlyPublished.forEach(post => {
    console.log(`- ${post.title} (${post.path})`);
  });
}

if (result.futurePosts.length > 0) {
  console.log('\nFuture posts:');
  result.futurePosts.forEach(post => {
    console.log(`- ${post.title} (${post.publishDate || post.date})`);
  });
}
