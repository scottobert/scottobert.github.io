---
title: "Automating PlantUML Diagrams in GitHub README with Actions and Confluence Sync"
date: 2025-07-02T09:00:00-07:00
draft: false
categories: ["Development Tutorials", "CI/CD"]
tags:
- GitHub Actions
- PlantUML
- Confluence
- Automation
- Documentation
- CI/CD
url: /posts/github-actions-plantuml-confluence-sync
---

Maintaining up-to-date documentation is crucial for any software project, but manually updating diagrams and keeping documentation synchronized across platforms can be time-consuming and error-prone. This guide demonstrates how to automate the entire workflow using GitHub Actions to generate PlantUML diagrams directly in your repository's README.md file and automatically synchronize the content to Confluence pages.

## The Complete Automation Pipeline

The solution we'll build consists of three main components: automatic PlantUML diagram generation from source files, embedding those diagrams into the README.md file, and synchronizing the updated content to Confluence. This approach ensures that your documentation stays current with every code change while maintaining consistency across platforms.

## Setting Up PlantUML Diagram Generation

First, we need to create a GitHub Actions workflow that can process PlantUML source files and generate diagrams. Create a `.github/workflows/update-diagrams.yml` file in your repository:

```yaml
name: Update PlantUML Diagrams and Sync to Confluence

on:
  push:
    branches: [ main ]
    paths: 
      - '**.puml'
      - 'README.md'
      - '.github/workflows/update-diagrams.yml'
  pull_request:
    branches: [ main ]
    paths:
      - '**.puml'
      - 'README.md'

jobs:
  update-diagrams:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    
    steps:
    - name: Checkout repository
      uses: actions/checkout@v4
      with:
        token: ${{ secrets.GITHUB_TOKEN }}
        fetch-depth: 0

    - name: Setup Java for PlantUML
      uses: actions/setup-java@v4
      with:
        distribution: 'temurin'
        java-version: '17'

    - name: Install PlantUML
      run: |
        wget -O plantuml.jar https://github.com/plantuml/plantuml/releases/latest/download/plantuml-1.2024.6.jar
        echo "PLANTUML_JAR=$PWD/plantuml.jar" >> $GITHUB_ENV

    - name: Generate PlantUML diagrams
      run: |
        find . -name "*.puml" -type f | while read -r file; do
          echo "Processing $file"
          java -jar $PLANTUML_JAR -tsvg "$file"
          # Also generate PNG for fallback
          java -jar $PLANTUML_JAR -tpng "$file"
        done

    - name: Update README with diagram references
      run: |
        python3 scripts/update-readme.py

    - name: Commit and push changes
      if: github.event_name == 'push'
      run: |
        git config --local user.email "action@github.com"
        git config --local user.name "GitHub Action"
        git add -A
        if git diff --staged --quiet; then
          echo "No changes to commit"
        else
          git commit -m "Auto-update PlantUML diagrams [skip ci]"
          git push
        fi

  sync-to-confluence:
    needs: update-diagrams
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    
    steps:
    - name: Checkout repository
      uses: actions/checkout@v4
      with:
        ref: main

    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'

    - name: Install dependencies
      run: |
        npm install markdown-it markdown-it-plantuml @atlassian/confluence-api

    - name: Sync to Confluence
      env:
        CONFLUENCE_URL: ${{ secrets.CONFLUENCE_URL }}
        CONFLUENCE_USERNAME: ${{ secrets.CONFLUENCE_USERNAME }}
        CONFLUENCE_API_TOKEN: ${{ secrets.CONFLUENCE_API_TOKEN }}
        CONFLUENCE_SPACE_KEY: ${{ secrets.CONFLUENCE_SPACE_KEY }}
        CONFLUENCE_PAGE_ID: ${{ secrets.CONFLUENCE_PAGE_ID }}
      run: |
        node scripts/sync-to-confluence.js
```

## Creating the README Update Script

The Python script that updates the README.md file with generated diagrams needs to be intelligent about finding and replacing diagram references. Create `scripts/update-readme.py`:

```python
#!/usr/bin/env python3
import os
import re
import sys
from pathlib import Path

def find_puml_files():
    """Find all .puml files in the repository."""
    puml_files = []
    for root, dirs, files in os.walk('.'):
        # Skip hidden directories and common build directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'build', 'dist']]
        for file in files:
            if file.endswith('.puml'):
                puml_files.append(os.path.join(root, file))
    return puml_files

def update_readme_with_diagrams(readme_path='README.md'):
    """Update README.md with generated diagram references."""
    if not os.path.exists(readme_path):
        print(f"README.md not found at {readme_path}")
        return False

    with open(readme_path, 'r', encoding='utf-8') as f:
        content = f.read()

    original_content = content
    puml_files = find_puml_files()
    
    for puml_file in puml_files:
        # Convert file path to relative path from repository root
        relative_path = os.path.relpath(puml_file, '.')
        base_name = os.path.splitext(relative_path)[0]
        
        # Generate both SVG and PNG references
        svg_path = f"{base_name}.svg"
        png_path = f"{base_name}.png"
        
        # Look for existing diagram markers in the README
        diagram_name = os.path.splitext(os.path.basename(puml_file))[0]
        
        # Pattern to match existing diagram sections
        pattern = rf'<!-- DIAGRAM:{diagram_name}:START -->.*?<!-- DIAGRAM:{diagram_name}:END -->'
        
        # Create the replacement content
        code_fence = "```"
        replacement = f'''<!-- DIAGRAM:{diagram_name}:START -->
![{diagram_name}]({svg_path})

*Diagram: {diagram_name.replace('-', ' ').replace('_', ' ').title()}*

<details>
<summary>View PlantUML Source asdf</summary>

{code_fence}plantuml
{read_puml_content(puml_file)}
{code_fence}

</details>
<!-- DIAGRAM:{diagram_name}:END -->'''

        if re.search(pattern, content, re.DOTALL):
            # Replace existing diagram section
            content = re.sub(pattern, replacement, content, flags=re.DOTALL)
            print(f"Updated existing diagram section for {diagram_name}")
        else:
            # Look for a placeholder to insert the diagram
            placeholder_pattern = rf'<!-- DIAGRAM:{diagram_name} -->'
            if re.search(placeholder_pattern, content):
                content = re.sub(placeholder_pattern, replacement, content)
                print(f"Inserted new diagram section for {diagram_name}")
            else:
                print(f"No placeholder found for {diagram_name}. Add '<!-- DIAGRAM:{diagram_name} -->' to README.md")

    # Only write if content changed
    if content != original_content:
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print("README.md updated successfully")
        return True
    else:
        print("No changes needed in README.md")
        return False

def read_puml_content(puml_file):
    """Read and return the content of a PlantUML file."""
    try:
        with open(puml_file, 'r', encoding='utf-8') as f:
            return f.read().strip()
    except Exception as e:
        print(f"Error reading {puml_file}: {e}")
        return f"Error reading file: {e}"

if __name__ == "__main__":
    success = update_readme_with_diagrams()
    sys.exit(0 if success else 1)
```

## Implementing Confluence Synchronization

The Confluence synchronization script converts the README.md content to Confluence-compatible markup and updates the specified page. Create `scripts/sync-to-confluence.js`:

```javascript
const fs = require('fs').promises;
const MarkdownIt = require('markdown-it');
const ConfluenceApi = require('@atlassian/confluence-api');

class ConfluenceSync {
    constructor() {
        this.confluence = new ConfluenceApi({
            host: process.env.CONFLUENCE_URL,
            username: process.env.CONFLUENCE_USERNAME,
            password: process.env.CONFLUENCE_API_TOKEN
        });
        
        this.spaceKey = process.env.CONFLUENCE_SPACE_KEY;
        this.pageId = process.env.CONFLUENCE_PAGE_ID;
        
        this.md = new MarkdownIt({
            html: true,
            linkify: true,
            typographer: true
        });
    }

    async convertMarkdownToConfluence(markdown) {
        // Convert markdown to HTML first
        let html = this.md.render(markdown);
        
        // Convert HTML to Confluence storage format
        html = this.convertHtmlToConfluence(html);
        
        return html;
    }

    convertHtmlToConfluence(html) {
        // Convert GitHub-flavored markdown elements to Confluence equivalents
        let confluence = html;
        
        // Convert code blocks
        confluence = confluence.replace(
            /<pre><code class="language-(\w+)">([\s\S]*?)<\/code><\/pre>/g,
            '<ac:structured-macro ac:name="code" ac:schema-version="1">' +
            '<ac:parameter ac:name="language">$1</ac:parameter>' +
            '<ac:plain-text-body><![CDATA[$2]]></ac:plain-text-body>' +
            '</ac:structured-macro>'
        );

        // Convert inline code
        confluence = confluence.replace(
            /<code>(.*?)<\/code>/g,
            '<code>$1</code>'
        );

        // Convert images to Confluence format
        confluence = confluence.replace(
            /<img src="([^"]+)" alt="([^"]*)"[^>]*>/g,
            (match, src, alt) => {
                if (src.startsWith('http')) {
                    return `<ac:image><ri:url ri:value="${src}" /></ac:image>`;
                } else {
                    // For local images, we'll need to upload them as attachments
                    return `<ac:image><ri:attachment ri:filename="${src.split('/').pop()}" /></ac:image>`;
                }
            }
        );

        // Convert headings
        confluence = confluence.replace(/<h([1-6])>(.*?)<\/h[1-6]>/g, '<h$1>$2</h$1>');

        // Convert lists
        confluence = confluence.replace(/<ul>/g, '<ul>');
        confluence = confluence.replace(/<\/ul>/g, '</ul>');
        confluence = confluence.replace(/<ol>/g, '<ol>');
        confluence = confluence.replace(/<\/ol>/g, '</ol>');
        confluence = confluence.replace(/<li>/g, '<li>');
        confluence = confluence.replace(/<\/li>/g, '</li>');

        return confluence;
    }

    async uploadAttachment(filePath, pageId) {
        try {
            const fileContent = await fs.readFile(filePath);
            const fileName = filePath.split('/').pop();
            
            const result = await this.confluence.putAttachment(
                pageId,
                fileName,
                fileContent,
                'image/svg+xml'
            );
            
            console.log(`Uploaded attachment: ${fileName}`);
            return result;
        } catch (error) {
            console.error(`Error uploading attachment ${filePath}:`, error.message);
            throw error;
        }
    }

    async syncReadmeToConfluence() {
        try {
            // Read the README.md file
            const readmeContent = await fs.readFile('README.md', 'utf8');
            
            // Convert to Confluence format
            const confluenceContent = await this.convertMarkdownToConfluence(readmeContent);
            
            // Get current page to preserve version
            const currentPage = await this.confluence.getPage(this.pageId);
            
            // Upload any local images as attachments
            await this.uploadLocalImages(readmeContent);
            
            // Update the page
            const updateData = {
                id: this.pageId,
                type: 'page',
                title: currentPage.title,
                space: {
                    key: this.spaceKey
                },
                body: {
                    storage: {
                        value: confluenceContent,
                        representation: 'storage'
                    }
                },
                version: {
                    number: currentPage.version.number + 1
                }
            };

            const result = await this.confluence.putPage(updateData);
            console.log(`Successfully updated Confluence page: ${result.title}`);
            console.log(`Page URL: ${process.env.CONFLUENCE_URL}/pages/viewpage.action?pageId=${this.pageId}`);
            
            return result;
        } catch (error) {
            console.error('Error syncing to Confluence:', error.message);
            throw error;
        }
    }

    async uploadLocalImages(markdownContent) {
        // Find all local image references
        const imageRegex = /!\[([^\]]*)\]\(([^)]+)\)/g;
        let match;
        
        while ((match = imageRegex.exec(markdownContent)) !== null) {
            const imagePath = match[2];
            
            // Skip external URLs
            if (!imagePath.startsWith('http') && !imagePath.startsWith('//')) {
                try {
                    await this.uploadAttachment(imagePath, this.pageId);
                } catch (error) {
                    console.warn(`Could not upload image ${imagePath}:`, error.message);
                }
            }
        }
    }
}

async function main() {
    try {
        const sync = new ConfluenceSync();
        await sync.syncReadmeToConfluence();
        console.log('Synchronization completed successfully');
    } catch (error) {
        console.error('Synchronization failed:', error.message);
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}
```

## Configuring Repository Secrets

For the automation to work properly, you need to configure several secrets in your GitHub repository settings. Navigate to your repository's Settings > Secrets and variables > Actions, and add the following secrets:

__CONFLUENCE_URL__: The base URL of your Confluence instance (e.g., `https://yourcompany.atlassian.net`).

__CONFLUENCE_USERNAME__: Your Confluence username or email address.

__CONFLUENCE_API_TOKEN__: Generate this from your Atlassian account settings under API tokens.

__CONFLUENCE_SPACE_KEY__: The key of the Confluence space where your page resides.

__CONFLUENCE_PAGE_ID__: The ID of the specific page you want to update. You can find this in the page URL or by using the Confluence API.

## Using the Automation System

To use this system in your repository, create PlantUML files with the `.puml` extension anywhere in your repository. For example, create `docs/architecture.puml`:

```text
@startuml architecture
!theme plain
skinparam backgroundColor white
skinparam defaultTextAlignment center

package "Frontend" {
    [React App]
    [Redux Store]
}

package "Backend Services" {
    [API Gateway]
    [Lambda Functions]
    [DynamoDB]
}

package "External Services" {
    [GitHub API]
    [Confluence API]
}

[React App] --> [Redux Store]
[React App] --> [API Gateway]
[API Gateway] --> [Lambda Functions]
[Lambda Functions] --> [DynamoDB]
[Lambda Functions] --> [GitHub API]
[Lambda Functions] --> [Confluence API]

@enduml
```

Then, in your README.md file, add a placeholder where you want the diagram to appear:

```markdown
# Project Architecture

Our system follows a modern serverless architecture pattern:

<!-- DIAGRAM:architecture -->

The architecture demonstrates the flow of data from the frontend React application through our serverless backend to external services.
```

When you commit and push these changes, the GitHub Action will automatically generate the diagram, update your README.md with the embedded SVG, and synchronize the content to your Confluence page.

## Advanced Customization Options

The system can be extended in several ways to meet specific requirements. You can modify the PlantUML generation to use different output formats, add custom styling themes, or include additional metadata in the generated diagrams.

For more complex documentation workflows, consider adding conditional logic to the Confluence sync script that handles different types of content differently. You might want to preserve certain sections of the Confluence page while only updating the automated portions.

The workflow can also be enhanced to support multiple Confluence pages, different diagram types, or integration with other documentation platforms like Notion or GitBook.

## Troubleshooting Common Issues

The most common issues occur with authentication and permissions. Ensure that your GitHub repository has the necessary permissions to write to the repository, and verify that your Confluence API token has the required permissions to update pages in the target space.

If diagrams are not generating correctly, check the PlantUML syntax and ensure that the Java environment is properly configured in the GitHub Action. The workflow includes error handling, but you may need to examine the Action logs for specific PlantUML compilation errors.

For Confluence synchronization issues, verify that the page ID and space key are correct, and that the API token has not expired. The Confluence API has rate limits, so consider adding retry logic for high-frequency updates.

This automated workflow transforms documentation maintenance from a manual chore into an seamless part of your development process, ensuring that your diagrams and documentation remain current and consistent across platforms.