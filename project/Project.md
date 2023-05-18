# Final Project - Secure Blog Hosting

## Scenario

Your organisation, that is in the market of software security, intends to host a blog to allow its developers to advertise their SecDevOps products and report their security analysis achievements to the world.
Naturally, the blog itself should be secure to uphold the company's good reputation.
They have assigned to your group, members of the secure software development team of the organisation, the role of designing and implementing a secure solution.

The blog shall be developed in the form of a modern web application, and support two components:

* **client**: a web page frontend that allows company employers to manage their personal content, and the general public to navigate its content.
* **server**: a backend with REST endpoints that is called by the client web page. Advanced users may also directly call the REST endpoints.

## Requirements

You shall design and build your blog according to the following general requirements:

- 1. **Interface**:
    * Each user shall have a personal content management service, which should allow in particular to:
        - Create, edit or delete blog posts;
        - Change the state of his/her blog posts between draft (only visible to the owner) or published (publicly visible);
        - Manage comments on his/her blog posts, e.g., enable or disable comments, remove comments, etc.
    * Blog posts shall support comments from existing/authenticated users or anonymous/non-authenticated users.
- 2. **Authentication**:
    * Users have to authenticate themselves to access their personal content management service.
    * You may use a minimal authentication method, e.g., password-based. If you see fit you may adopt more secure and state-of-the-art solutions such as enforcing secure HTTPS communication for authenticated users. Note, however, that authentication and secure communication are **not** the primary focus of this project.
- 3. **Access control**:
    * Only the owner shall have access to his/her content management service.
    * All published blog posts are public.

You are **not** required to provide more advanced functionality, but if you wish to do so remember to clearly consider and document its security requirements.

## Design

Your team shall design the software components needed for the blog, coupled with the security mechanisms to satisfy the requirements outlined above.
You shall seek to adopt a security by design software development methodology, popularly called SecDevOps in the industry. A natural direction is to design a system architecture, specify actors and use/misuse cases, and identify security threats and assumptions before writing a single line of code. A more detailed description of such a general methodology is described in the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/).

The security goal of this project is to protect against external client-side attackers or malicious users.
You may assume that, aside from vulnerabilities in design or implementation (including third-party dependencies), the server and the authentication method are trusted.

## Implementation

You shall implement a functional blog that meets the above general requirements and instantiates your proposed secure design.
You can use any technology and programming language for the server/client code that you see fit. 

Beyond familiarity with technology or ease of deployment, your choice shall take into consideration the reliability and the security guarantees offered by each technology. Secure and reliable software procurement is also a job of security developers and teams. 

You are not limited in any way in the existing frameworks that you can use. In fact, you are encouraged to reuse and adapt popular open-source blogging frameworks for your context (to the extent of your interest in exploring other projects). You may also opt to implement a simple prototype *from scratch*. Note that the least source code you develop, and the largest the *trusted* code base you reuse, the more important it is to demonstrate that you understand the configurations of the software components that you reuse, how they fulfil your requirements and which are their security implications. 
As a starting point for exploring existing open-source projects, you may consider the following non-exclusive nor curated lists:

* blog hosting platforms (frontend-oriented): [WordPress](https://github.com/WordPress/WordPress), [Joomla](https://github.com/joomla/joomla-cms), [Ghost](https://github.com/TryGhost/Ghost), [Drupal](https://github.com/drupal/drupal), [SilverStripe](https://github.com/silverstripe/silverstripe-framework), [Jekyll](https://github.com/jekyll/jekyll), [Bolt](https://github.com/bolt/bolt), [Poet](https://github.com/jsantell/poet), [Nikola](https://github.com/getnikola/nikola), [Hexo](https://github.com/hexojs/hexo), [Hugo](https://github.com/gohugoio/hugo)
* headless content management systems (backend-oriented): [TinaCMS](https://github.com/tinacms/tinacms), [Jamstack CMS](https://jamstack.org/headless-cms/), [Gentics Mesh](https://github.com/gentics/mesh/), [Decap CMS](https://github.com/decaporg/decap-cms), [Ponzu CMS](https://github.com/ponzu-cms/ponzu)


## Analysis

You shall also seek to demonstrate that your implementation respects your design and fulfils its security requirements.
You shall describe the security analysis methodology that you have employed to validate your implementation and corroborate the overall security of your system. If you adapt existing frameworks, you are expected to detail the security analysis methodology that they may already have in place and to complement them with some additional analyses of your own.

You may check the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/) for a more detailed description of classical security analyses.
Also, remember the more advanced security analysis tools and/or techniques that we have seen in the practical labs, and explore which are can be applied to your context. Your analysis may include, e.g.:

- security guarantees offered by the programming languages;
- adopted secure software design patterns;
- security analysis of dependencies or external libraries;
- adopted mitigations for common vulnerabilities;
- security testing methodologies (manual or automated) that you have put in place;
- source code analysis tools that you have integrated in your development.

## Report

The project report must describe your design, implementation and analysis. The report shall primarily focus on design and analysis decisions, in detriment of implementation details.

Remember that software design, implementation and analysis are not independent phases but are part of a continuous software development process.
Any lessons that you have learned along the way, such as implementation details that have led you to revisit your initial design or design/implementation vulnerabilities that you had not initially predicted, e.g. when designing use and misuse cases, but have found through later analysis, are valuable information to include in the project report.

## Presentation

At the end of the semester, each group will present their assignments during classes. The presentation shall highlight the most relevant security-oriented details of the design/implementation/analysis, as in the written report, and showcase common uses of your service.

## Grading

Each component will have the following percentage in the project's final grade:

| Component              |  %   |
| ---------------------- | ---- |
| Design                 |  25  |
| Implementation         |  25  |
| Analysis               |  30  |
| Presentation & Report  |  20  |
