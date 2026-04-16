# [Stage | Idea Generation] Diabolical eBPF Field Manual

[A comprehensive collection](https://mbhatt1.github.io/dBPF/) of advanced eBPF security techniques and exploits, presented as a field manual for security researchers and practitioners.

## Overview

This repository contains the source for the Diabolical eBPF Field Manual, a detailed exploration of eBPF security concepts, vulnerabilities, and exploitation techniques. The content is organized as a series of technical articles covering various aspects of eBPF security.

## Project Structure

- `_posts/`: Contains individual articles organized by date
- `_layouts/`: Custom Jekyll layouts
- `_includes/`: Reusable HTML components
- `assets/`: Static assets including CSS
- `index.md`: Main landing page

## Local Development

### Prerequisites

- Ruby (version specified in `.ruby-version`)
- Bundler

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/Diabolial_eBPF_Field_Manual_site.git
cd Diabolial_eBPF_Field_Manual_site
```

2. Install dependencies:
```bash
bundle install
```

3. Run the development server:
```bash
bundle exec jekyll serve --host=localhost --livereload
```

The site will be available at `http://localhost:4000`

## Contributing

1. Fork the repository
2. Create a new branch for your changes
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

Thanks to all contributors and researchers in the eBPF security community who have made this field manual possible.
