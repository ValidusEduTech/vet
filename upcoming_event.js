document.addEventListener('DOMContentLoaded', () => {
    const timelineEvents = document.querySelectorAll('.timeline-event');
    const progressBar = document.querySelector('.timeline-progress');

    const updateProgressBar = () => {
        const windowHeight = window.innerHeight;
        const documentHeight = document.documentElement.scrollHeight;
        const scrollPosition = window.scrollY;
        
        const scrollPercentage = (scrollPosition / (documentHeight - windowHeight)) * 100;
        progressBar.style.height = `${Math.min(scrollPercentage, 100)}%`;
    };

    window.addEventListener('scroll', updateProgressBar);
});